from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config.settings import settings
from src.config.database import startDB

from src.routes import auth, items, users

app = FastAPI()

origins = [
    settings.CLIENT_ORIGIN,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def start_dependencies():
    await startDB()


app.include_router(auth.router, tags=['Auth'], prefix='/api/auth')
app.include_router(users.router, tags=['Users'], prefix='/api/users')
app.include_router(items.router, tags=['Items'], prefix='/api/items')

@app.get("/api/healthchecker")
def root():
    return {"message": "Welcome to FastAPI with MongoDB"}
