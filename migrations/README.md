This directory is reserved for Flask-Migrate revisions.

The application uses `db.create_all()` for a simple first-run experience in development. For managed schema migrations, initialize and generate revisions with:

```bash
flask db init
flask db migrate -m "Initial schema"
flask db upgrade
```
