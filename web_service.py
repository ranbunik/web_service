from flask import Flask, request, jsonify, send_file
import json
import os
from datetime import datetime

app = Flask(__name__)

# קובץ JSON לאחסון הנתונים
JSON_FILE = 'data.json'

def load_data():
    """טעינת נתונים מקובץ JSON"""
    if os.path.exists(JSON_FILE):
        with open(JSON_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_data(data):
    """שמירת נתונים לקובץ JSON"""
    with open(JSON_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

@app.route('/add', methods=['GET'])
def add_data():
    """
    קבלת 4 פרמטרים דרך URL והוספתם לקובץ JSON
    דוגמה: http://your-server.com/add?param1=value1&param2=value2&param3=value3&param4=value4
    """
    try:
        # קבלת הפרמטרים מה-URL
        param1 = request.args.get('param1')
        param2 = request.args.get('param2')
        param3 = request.args.get('param3')
        param4 = request.args.get('param4')
        
        # בדיקה שכל הפרמטרים התקבלו
        if not all([param1, param2, param3, param4]):
            return jsonify({
                'status': 'error',
                'message': 'יש לספק את כל 4 הפרמטרים: param1, param2, param3, param4'
            }), 400
        
        # טעינת הנתונים הקיימים
        data = load_data()
        
        # יצירת רשומה חדשה
        new_entry = {
            'id': len(data) + 1,
            'timestamp': datetime.now().isoformat(),
            'param1': param1,
            'param2': param2,
            'param3': param3,
            'param4': param4
        }
        
        # הוספת הרשומה לנתונים
        data.append(new_entry)
        
        # שמירה לקובץ
        save_data(data)
        
        return jsonify({
            'status': 'success',
            'message': 'הנתונים נשמרו בהצלחה',
            'entry': new_entry
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'שגיאה: {str(e)}'
        }), 500

@app.route('/view', methods=['GET'])
def view_data():
    """צפייה בכל הנתונים בקובץ JSON"""
    try:
        data = load_data()
        return jsonify({
            'status': 'success',
            'count': len(data),
            'data': data
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'שגיאה: {str(e)}'
        }), 500

@app.route('/download', methods=['GET'])
def download_data():
    """הורדת קובץ ה-JSON"""
    try:
        if os.path.exists(JSON_FILE):
            return send_file(JSON_FILE, as_attachment=True)
        else:
            return jsonify({
                'status': 'error',
                'message': 'קובץ הנתונים לא קיים'
            }), 404
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'שגיאה: {str(e)}'
        }), 500

@app.route('/clear', methods=['GET'])
def clear_data():
    """מחיקת כל הנתונים (שימוש זהיר!)"""
    try:
        save_data([])
        return jsonify({
            'status': 'success',
            'message': 'כל הנתונים נמחקו'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'שגיאה: {str(e)}'
        }), 500

@app.route('/', methods=['GET'])
def home():
    """דף הבית - הוראות שימוש"""
    return jsonify({
        'service': 'Web Service for Data Collection',
        'endpoints': {
            '/add': 'הוספת נתונים (GET) - param1, param2, param3, param4',
            '/view': 'צפייה בכל הנתונים (GET)',
            '/download': 'הורדת קובץ JSON (GET)',
            '/clear': 'מחיקת כל הנתונים (GET)'
        },
        'example': '/add?param1=ערך1&param2=ערך2&param3=ערך3&param4=ערך4'
    })

if __name__ == '__main__':
    # הרצה על כל הממשקים (0.0.0.0) בפורט 5000
    app.run(host='0.0.0.0', port=5000, debug=True)
