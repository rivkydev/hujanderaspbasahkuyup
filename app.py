from flask import Flask, render_template, send_from_directory
import os

app = Flask(__name__)

# Folder tempat kamu menyimpan file .exe
DOWNLOAD_FOLDER = 'downloads'
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download')
def download_file():
    filename = "PBMacro.exe"
    return send_from_directory(app.config['DOWNLOAD_FOLDER'], filename)

if __name__ == '__main__':
    if not os.path.exists(DOWNLOAD_FOLDER):
        os.makedirs(DOWNLOAD_FOLDER)
    app.run(debug=True)