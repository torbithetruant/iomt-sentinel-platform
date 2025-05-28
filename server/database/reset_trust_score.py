import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import update, select
from models import AsyncSessionLocal, DeviceTrust
from datetime import datetime, timezone

async def reset_all_trust_scores():
    async with AsyncSessionLocal() as db:
        # Sélectionner tous les devices trust
        result = await db.execute(select(DeviceTrust.device_id))
        device_ids = [row[0] for row in result.all()]

        if not device_ids:
            print("✅ Aucun device trust à réinitialiser.")
            return

        for device_id in device_ids:
            await db.execute(
                update(DeviceTrust)
                .where(DeviceTrust.device_id == device_id)
                .values(
                    trust_score=1.0,
                    updated_at=datetime.now(timezone.utc)
                )
            )
            print(f"🔄 Trust score reset for {device_id}")

        await db.commit()
        print("✅ Tous les trust scores ont été réinitialisés à 1.0.")

# Lance le script
if __name__ == "__main__":
    asyncio.run(reset_all_trust_scores())
