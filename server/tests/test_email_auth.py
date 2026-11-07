import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import Base
from app.main import create_app
from app.pottery import profile


@pytest.fixture()
def client(tmp_path):
    settings = Settings(_env_file=None, admin_password="x" * 16, secret_key="y" * 40,
                        database_url="sqlite:///" + str(tmp_path / "t.db"), llm_mode="demo",
                        environment="development")
    app = create_app(settings, configuration_path=tmp_path / ".env")
    Base.metadata.create_all(app.state.engine)
    with TestClient(app) as c:
        yield c


def create_guest_project(client):
    document = {"name": "待迁移作品", "profile": profile("vase"), "height": 28,
                "material": "terracotta", "gloss": 25, "preset": "vase"}
    body = client.post("/api/v1/workbenches", json={"document": document}).json()["data"]
    return body["project"], body["session_token"]


def request_code(client, email="maker@example.com"):
    response = client.post("/api/v1/auth/email/request", json={"email": email})
    assert response.status_code == 200
    return response.json()["data"]["development_code"]


def verify(client, email, code, guest_projects=None):
    return client.post("/api/v1/auth/email/verify", json={
        "email": email,
        "code": code,
        "guest_projects": guest_projects or [],
    })


def test_email_login_and_guest_project_migration(client):
    project, session_token = create_guest_project(client)
    email = "maker@example.com"
    code = request_code(client, email)
    response = verify(client, email, code, [{
        "project_id": project["id"],
        "session_token": session_token,
    }])
    assert response.status_code == 200
    login = response.json()["data"]
    headers = {"Authorization": "Bearer " + login["access_token"]}

    me = client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["data"]["email"] == email

    projects = client.get("/api/v1/pottery/projects", headers=headers)
    assert projects.status_code == 200
    assert [item["id"] for item in projects.json()["data"]] == [project["id"]]

    read = client.get(
        f"/api/v1/workbenches/{project['id']}",
        headers={**headers, "X-Session-Token": session_token},
    )
    assert read.status_code == 200


def test_other_user_cannot_read_migrated_project(client):
    project, session_token = create_guest_project(client)
    first = request_code(client, "first@example.com")
    login = verify(client, "first@example.com", first, [{
        "project_id": project["id"], "session_token": session_token,
    }]).json()["data"]

    second_code = request_code(client, "second@example.com")
    second = verify(client, "second@example.com", second_code).json()["data"]
    second_headers = {"Authorization": "Bearer " + second["access_token"]}

    response = client.get(f"/api/v1/workbenches/{project['id']}", headers=second_headers)
    assert response.status_code == 404


def test_wrong_code_and_logout(client):
    email = "maker@example.com"
    request_code(client, email)
    assert verify(client, email, "000000").status_code == 400

    code = request_code(client, email)
    login_response = verify(client, email, code)
    assert login_response.status_code == 200
    headers = {"Authorization": "Bearer " + login_response.json()["data"]["access_token"]}
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
