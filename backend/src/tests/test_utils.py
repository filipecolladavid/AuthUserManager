async def login(username, password, client):
    response = await client.post(
        "/auth/login",
        data={
            "username": username,
            "password": password
        }
    )
    assert response.status_code == 200


async def logout(client):
    response = await client.get("/auth/logout")
    assert response.status_code == 200