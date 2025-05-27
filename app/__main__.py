import uvicorn

from app.api import app

if __name__ == "__main__":
    uvicorn.run(app, port=8000, host="0.0.0.0")
