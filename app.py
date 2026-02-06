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

# Vercel serverless function handler
if __name__ != '__main__':
    # This is for Vercel
    application = app