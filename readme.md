# Clone the repository
git clone https://github.com/username/fastauth.git
cd fastauth

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate

# Install project dependencies
pip install -r requirements.txt

# Set up your environment variables in the .env file
DATABASE_URL=mysql+pymysql://root:yourpassword@localhost/fastauth
SECRET_KEY=your_secret_key_here

# To start the FastAPI server, run the following command
uvicorn app.main:app --reload

# Run the following command to generate a migration file
alembic revision --autogenerate -m "Migration message here"

# To apply the migrations to your database, run
alembic upgrade head

# To stop the server from running cleanly, on the root folder, you can use
python -m kill_unicorn