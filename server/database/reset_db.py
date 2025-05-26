import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from models import Base, DATABASE_URL

# Crée un moteur async avec echo pour voir les requêtes SQL
engine = create_async_engine(DATABASE_URL, echo=True)

async def reset_db():
    async with engine.begin() as conn:
        print("❌ Dropping all tables...")
        await conn.run_sync(Base.metadata.drop_all)

        print("✅ Recreating all tables...")
        await conn.run_sync(Base.metadata.create_all)

    await engine.dispose()
    print("🎉 Database reset complete.")

if __name__ == "__main__":
    asyncio.run(reset_db())
