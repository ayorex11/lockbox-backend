from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("vault", "0001_initial"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="auditevent",
            index=models.Index(
                fields=["event_type", "created_at"], name="audit_type_created_idx"
            ),
        ),
    ]
