# Tasks executor app
This is an application that executes bash commands in docker containers.


# How to run the project
1. Clone the repository
```bash
git clone https://github.com/v-vlasenko/tasks-executor.git
```

2. Go into directory and set up the virtual environment
```bash
cd tasks-executor
python -m venv venv
source venv/bin/activate
```

3. Configure environment variables: create a `.env` file in root folder with following variables:
```
FLASK_APP=task_executor.py
DATABASE_URL=sqlite:///app.db
FLASK_SECRET_KEY=<your-secret-key>
JWT_SECRET_KEY=<your-sercret-key>
```

4. Install requirements (dependencies)
```bash
pip install -r requirements.txt
```

5. Create SQLite database by running upgrade command (you will notice a file named app.db is added after this command finishes)
```bash
flask db upgrade
```

6. Finally run the application with 
```bash
flask run
```

