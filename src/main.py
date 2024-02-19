"""This is application creates temporary passwords that are saved on a SQLite3 database."""
from fastapi import fastapi
from fastapi.security import 0Auth2PasswordBearer
from sqlite3 import connect
from datetime import datetime, timedelta

# Set the App
app = FastAPI()

# Set the database
db = "tempass.db"

# Create table if not exists
with connect(db) as connection:
  cursor = connection.cursor()
  cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS temporary_passwords (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      password TEXT,
      created_at DATETIME,
      expiration_time DATETIME
    )
    """
  )
  connection.commit()

# Security 
oauth2_scheme = 0Auth2PasswordBearer(tokenURL="token")


def main():


if __name__ == '__main__':
  main()
