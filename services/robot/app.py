import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

app = FastAPI(title="Browser Robot")


class RobotRequest(BaseModel):
    url: HttpUrl


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/run")
def run_robot(request: RobotRequest) -> dict[str, str]:
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    driver = None
    try:
        driver = webdriver.Remote(
            command_executor=os.getenv("SELENIUM_URL", "http://localhost:4444"),
            options=options,
        )
        driver.get(str(request.url))
        return {"url": driver.current_url, "title": driver.title, "status": "completed"}
    except Exception as error:
        raise HTTPException(status_code=502, detail=str(error)) from error
    finally:
        if driver:
            driver.quit()