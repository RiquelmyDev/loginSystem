from flask import Flask, request, render_template, redirect, session
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'  # essa é a chave para sessões

# Função para conectar ao banco de dados
def create_connection():
    return sqlite3.connect('users.db')

# Criar tabela de usuários, se ela ainda não existir
def create_table():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

# Rota para o registro de usuários
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash da senha
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = create_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
            conn.commit()
        except sqlite3.IntegrityError:
            return 'O nome de usuário já existe'

        return redirect('/login')
    return render_template('register.html')

# Rota para login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = create_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        # Verificar se o usuário existe e se a senha é válida
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
            session['username'] = username
            return redirect('/dashboard')
        else:
            return "Falha no login, tente novamente!"

    return render_template('login.html')

# Rota para a dashboard, acessível apenas se o usuário estiver logado
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return f"Bem-vindo, {session['username']}! Você está logado."
    return redirect('/login')

# Rota para logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

# Iniciar o servidor Flask
if __name__ == "__main__":
    create_table()  # Criar a tabela no banco de dados, se não existir
    app.run(debug=True)  # Rodar o servidor localmente

                                        
#teste