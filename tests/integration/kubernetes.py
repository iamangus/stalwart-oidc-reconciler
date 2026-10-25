#!/usr/bin/env python3
"""Run real Community-edition tests in an ephemeral Kubernetes namespace.

Requires kubectl, Python requests, and Go. Uses no production credentials,
publishes no ingress/service/MX, and deletes only the namespace it just created.
All test credentials are generated at runtime and never printed.
"""
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time

import requests

ROOT = Path(__file__).resolve().parents[2]
NS = "stalwart-reconciler-test-" + secrets.token_hex(4)
DOMAIN = "reconciler-test.example.com"
with socket.socket() as port_probe:
    port_probe.bind(("127.0.0.1", 0))
    PORT = port_probe.getsockname()[1]
created = False
forward = None


def kubectl(*args, document=None):
    return subprocess.run(
        ["kubectl", *args],
        input=json.dumps(document) if document is not None else None,
        text=True, capture_output=True, check=True,
    ).stdout


def wait_request(session, method, path, **kwargs):
    for _ in range(90):
        if forward is not None and forward.poll() is not None:
            raise RuntimeError("Isolated fixture port-forward exited")
        try:
            response = session.request(method, f"http://127.0.0.1:{PORT}" + path,
                                       timeout=5, **kwargs)
            if response.ok:
                return response
        except requests.RequestException:
            pass
        time.sleep(2)
    raise RuntimeError("Timed out waiting for isolated Stalwart API")


def jmap(session, method, args):
    response = wait_request(session, "POST", "/jmap", json={
        "using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
        "methodCalls": [[method, args, "r1"]],
    })
    rows = response.json().get("methodResponses", [])
    if len(rows) != 1 or rows[0][0] != method:
        raise RuntimeError("Isolated JMAP method rejected: " + method)
    return rows[0][1]


try:
    kubectl("create", "-f", "-", document={
        "apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NS},
    })
    created = True
    password = secrets.token_urlsafe(32)
    kubectl("create", "-f", "-", document={
        "apiVersion": "v1", "kind": "Secret", "metadata": {"namespace": NS, "name": "fixture"},
        "stringData": {"STALWART_RECOVERY_ADMIN": "admin:" + password},
    })
    kubectl("create", "-f", "-", document={
        "apiVersion": "v1", "kind": "Pod", "metadata": {"namespace": NS, "name": "stalwart"},
        "spec": {
            "activeDeadlineSeconds": 600,
            "automountServiceAccountToken": False,
            "securityContext": {"fsGroup": 2000},
            "containers": [{
                "name": "stalwart", "image": "docker.io/stalwartlabs/stalwart:v0.16.27",
                "envFrom": [{"secretRef": {"name": "fixture"}}],
                "env": [{"name": "STALWART_PUBLIC_URL", "value": f"http://127.0.0.1:{PORT}"}],
                "ports": [{"containerPort": 8080}],
                "readinessProbe": {"tcpSocket": {"port": 8080}, "periodSeconds": 1,
                                   "failureThreshold": 90},
                "resources": {"requests": {"cpu": "100m", "memory": "256Mi"},
                              "limits": {"cpu": "2", "memory": "1Gi"}},
                "volumeMounts": [{"name": "etc", "mountPath": "/etc/stalwart"},
                                 {"name": "data", "mountPath": "/var/lib/stalwart"}],
            }],
            "volumes": [{"name": "etc", "emptyDir": {}}, {"name": "data", "emptyDir": {}}],
        },
    })
    kubectl("-n", NS, "wait", "--for=condition=Ready", "pod/stalwart", "--timeout=180s")
    forward = subprocess.Popen(["kubectl", "-n", NS, "port-forward", "pod/stalwart", f"{PORT}:8080"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    session = requests.Session()
    session.auth = ("admin", password)
    bootstrap = jmap(session, "x:Bootstrap/get", {"ids": ["singleton"]})
    assert bootstrap.get("list"), "Bootstrap object unavailable"
    response = jmap(session, "x:Bootstrap/set", {"update": {"singleton": {
        "serverHostname": "mail." + DOMAIN, "defaultDomain": DOMAIN,
        "requestTlsCertificate": False, "generateDkimKeys": False,
        "dataStore": {"@type": "RocksDb", "path": "/var/lib/stalwart/data"},
        "directory": {"@type": "Internal"}, "dnsServer": {"@type": "Manual"},
    }}})
    if response.get("notUpdated"):
        # Bootstrap validation failures contain no submitted credentials.
        raise RuntimeError("Bootstrap validation: " + json.dumps(response["notUpdated"]))
    admin = response["updated"]["singleton"]
    print("Bootstrapped isolated Stalwart v0.16.27 (no DNS records or public listeners exposed)")
    if forward:
        forward.terminate()
        forward.wait(timeout=10)
        forward = None
    kubectl("-n", NS, "exec", "stalwart", "--", "/bin/sh", "-c", "kill -TERM 1")
    kubectl("-n", NS, "wait", "--for=jsonpath={.status.containerStatuses[0].restartCount}=1",
            "pod/stalwart", "--timeout=180s")
    kubectl("-n", NS, "wait", "--for=condition=Ready", "pod/stalwart", "--timeout=180s")
    forward = subprocess.Popen(["kubectl", "-n", NS, "port-forward", "pod/stalwart", f"{PORT}:8080"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    session.auth = (admin["username"], admin["secret"])
    account_info = wait_request(session, "GET", "/api/account").json()
    assert account_info.get("edition") in ("oss", "community"), "Fixture unexpectedly runs Enterprise edition"
    domains = jmap(session, "x:Domain/get", {"ids": None, "properties": ["id", "name"]})["list"]
    domain_id = next(d["id"] for d in domains if d["name"] == DOMAIN)
    # Stalwart requires an account creator to hold every permission it grants.
    # Use a dedicated empty user account with normal-user permissions plus only
    # the registry operations required by the reconciler. No impersonation or
    # account-deletion permission is granted.
    actor = jmap(session, "x:Account/set", {"create": {"actor": {
        "@type": "User", "name": "reconciler", "domainId": domain_id,
        "description": "Isolated reconciliation actor", "roles": {"@type": "User"},
        "permissions": {"@type": "Merge", "enabledPermissions": {
            "sysDomainGet": True, "sysAccountGet": True,
            "sysAccountQuery": True, "sysAccountCreate": True, "sysAccountUpdate": True,
        }},
    }}})
    if actor.get("notCreated"):
        raise RuntimeError("Provisioning actor creation rejected")
    actor_id = actor["created"]["actor"]["id"]
    key = jmap(session, "x:ApiKey/set", {"accountId": actor_id, "create": {"test": {
        "description": "Ephemeral reconciler integration test",
        "permissions": {"@type": "Inherit"},
    }}})
    if key.get("notCreated"):
        raise RuntimeError("Test API key rejected")
    token = key["created"]["test"]["secret"]
    with tempfile.TemporaryDirectory(prefix="stalwart-integration-", dir="/tmp/opencode") as tmp:
        path = Path(tmp) / "token"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(token)
        env = dict(os.environ, STALWART_INTEGRATION_ALLOW_WRITES="1",
                   STALWART_TEST_URL=f"http://127.0.0.1:{PORT}", STALWART_TEST_TOKEN_FILE=str(path),
                   STALWART_TEST_DOMAIN_ID=domain_id, STALWART_TEST_DOMAIN=DOMAIN)
        subprocess.run(["go", "test", "-count=1", "-v", "./tests/integration"], cwd=ROOT, env=env, check=True)
finally:
    if sys.exc_info()[0] and created:
        result = subprocess.run(["kubectl", "-n", NS, "logs", "stalwart", "--tail=30"],
                                text=True, capture_output=True)
        for line in result.stdout.splitlines():
            if not any(word in line.lower() for word in ["password", "secret", "token", "credential"]):
                print("Fixture diagnostic:", line)
    if forward:
        forward.terminate()
        forward.wait(timeout=10)
    if created:
        kubectl("delete", "namespace", NS, "--wait=true", "--timeout=120s")
        print("Removed isolated test namespace:", NS)
