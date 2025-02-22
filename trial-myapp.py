from flask import Flask, request, jsonify

app = Flask(__name__)

# 仮のユーザーデータ
users = {
    "TaroYamada": {
        "password": "PaSswd4TY",
        "nickname": "たろー",
        "comment": "僕は元気です"
    }
}

# ユーザ登録 (POST /signup)
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    user_id = data.get("user_id")
    password = data.get("password")
    nickname = data.get("nickname")
    comment = data.get("comment")

    if user_id in users:
        return jsonify({"error": "User already exists"}), 400

    users[user_id] = {
        "password": password,
        "nickname": nickname,
        "comment": comment
    }
    return jsonify({"message": "User created successfully"}), 201

# ユーザ情報取得 (GET /users/{user_id})
@app.route("/users/<user_id>", methods=["GET"])
def get_user(user_id):
    user = users.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "user_id": user_id,
        "nickname": user["nickname"],
        "comment": user["comment"]
    })

# ユーザ情報更新 (PATCH /users/{user_id})
@app.route("/users/<user_id>", methods=["PATCH"])
def update_user(user_id):
    if user_id not in users:
        return jsonify({"error": "User not found"}), 404

    data = request.json
    if "nickname" in data:
        users[user_id]["nickname"] = data["nickname"]
    if "comment" in data:
        users[user_id]["comment"] = data["comment"]

    return jsonify({"message": "User updated successfully"})

# ユーザアカウント削除 (POST /close)
@app.route("/close", methods=["POST"])
def close_account():
    data = request.json
    user_id = data.get("user_id")

    if user_id not in users:
        return jsonify({"error": "User not found"}), 404

    del users[user_id]
    return jsonify({"message": "User account deleted successfully"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

