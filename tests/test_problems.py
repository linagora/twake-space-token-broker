from httpx import AsyncClient


async def test_an_unknown_path_answers_a_problem(client: AsyncClient) -> None:
    response = await client.get("/nothing")

    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["type"] == "urn:twake:problem:not_found"
    assert response.json()["code"] == "not_found"


async def test_a_wrong_method_answers_a_problem(client: AsyncClient) -> None:
    response = await client.post("/forward-auth")

    assert response.status_code == 405
    assert response.json()["code"] == "method_not_allowed"
