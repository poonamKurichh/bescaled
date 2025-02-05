from app import create_app

app = create_app()  # ✅ No conflicts, correctly initializes the app

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5555, debug=True)