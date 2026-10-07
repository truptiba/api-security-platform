import psycopg2

connection = psycopg2.connect(
    host="localhost",
    port="5432",
    database="api_security",
    user="postgres",
    password="trupti07"
)

print("Database connected successfully!")