from flask import Flask, jsonify, request, abort
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_talisman import Talisman
from datetime import timedelta

app = Flask(__name__)

# Configuração da chave secreta para JWT
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Troque por uma chave secreta real
jwt = JWTManager(app)

# Configuração do Flask-Limiter para limitação de taxa
limiter = Limiter(app, key_func=lambda: request.remote_addr, default_limits=["200 per day", "50 per hour"])

# Configuração do Flask-Talisman para cabeçalhos de segurança
csp = {
    'default-src': ["'self'"],
    'img-src': ["'self'", "https://trusted.com"],
    'script-src': ["'self'", "'unsafe-inline'"],
}
Talisman(app, content_security_policy=csp)

# Usuários de exemplo (em um cenário real, use um banco de dados seguro)
users = {
    "admin": {"password": "adminpass", "role": "admin", "id": 1},
    "user1": {"password": "user1pass", "role": "user", "id": 2},
}

# Rota para autenticação e geração de token JWT
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    
    user = users.get(username)
    if not user or user['password'] != password:
        abort(401, "Credenciais inválidas")
    
    access_token = create_access_token(identity={'username': username, 'role': user['role'], 'id': user['id']}, expires_delta=timedelta(minutes=30))
    return jsonify(access_token=access_token)

# Função para verificar se o usuário tem permissão
def check_permission(user_id):
    current_user = get_jwt_identity()
    if current_user['role'] == 'admin':
        return True
    elif current_user['id'] == user_id:
        return True
    return False

# Endpoint protegido /api/users/{id}
@app.route('/api/users/<int:id>', methods=['GET'])
@jwt_required()
@limiter.limit("10 per minute")
def get_user(id):
    if not check_permission(id):
        abort(403, "Você não tem permissão para acessar este recurso.")
    
    return jsonify({"user_id": id, "message": "Recurso acessado com sucesso!"})

# Tratamento de erro para acesso negado
@app.errorhandler(403)
def forbidden(e):
    return jsonify(error=str(e)), 403

@app.errorhandler(401)
def unauthorized(e):
    return jsonify(error="Unauthorized: " + str(e)), 401

if __name__ == '__main__':
    app.run(debug=True)
