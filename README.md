# שירות Web פשוט לאיסוף נתונים

## תיאור
שירות HTTP פשוט שמקבל 4 פרמטרים דרך URL ושומר אותם בקובץ JSON.

## התקנה והרצה מקומית

### דרישות מוקדמות
- Python 3.7 ומעלה
- pip

### שלבי התקנה
```bash
# התקנת תלויות
pip install -r requirements.txt

# הרצת השירות
python web_service.py
```

השירות ירוץ על http://localhost:5000

## Endpoints זמינים

### 1. הוספת נתונים
```
GET /add?param1=value1&param2=value2&param3=value3&param4=value4
```
**דוגמה:**
```
http://localhost:5000/add?param1=שם&param2=גיל&param3=עיר&param4=תיאור
```

### 2. צפייה בנתונים
```
GET /view
```
מחזיר את כל הנתונים שנשמרו בפורמט JSON

### 3. הורדת קובץ JSON
```
GET /download
```
מוריד את קובץ הנתונים המלא

### 4. מחיקת נתונים
```
GET /clear
```
מוחק את כל הנתונים (שימוש זהיר!)

### 5. דף הבית
```
GET /
```
מציג את רשימת ה-endpoints הזמינים

## פריסה לאינטרנט

### אופציה 1: Render.com (חינם)
1. צור חשבון ב-https://render.com
2. לחץ על "New +" ובחר "Web Service"
3. חבר את הקוד (מ-GitHub או העלאה ישירה)
4. הגדרות:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `python web_service.py`
5. לחץ על "Create Web Service"

### אופציה 2: PythonAnywhere (חינם)
1. צור חשבון ב-https://www.pythonanywhere.com
2. העלה את הקבצים לחשבון שלך
3. צור Web App חדש עם Flask
4. הגדר את web_service.py כקובץ הראשי

### אופציה 3: Heroku
```bash
# הוסף קובץ Procfile
echo "web: python web_service.py" > Procfile

# הגדר את הפורט מ-environment variable
# שנה בקוד: port=int(os.environ.get('PORT', 5000))
```

### אופציה 4: Railway.app (חינם)
1. צור חשבון ב-https://railway.app
2. העלה את הקוד או חבר GitHub
3. Railway יזהה אוטומטית את Flask
4. השירות יהיה זמין באינטרנט

## אבטחה (חשוב!)

**⚠️ אזהרת אבטחה:** השירות הזה פתוח לכולם ללא הגנה!

לשיפור האבטחה, מומלץ להוסיף:

### 1. אימות בסיסי עם API Key
```python
API_KEY = 'your-secret-key-here'

@app.before_request
def check_api_key():
    if request.endpoint != 'home':
        key = request.args.get('api_key')
        if key != API_KEY:
            return jsonify({'error': 'Unauthorized'}), 401
```

שימוש:
```
http://your-server.com/add?api_key=your-secret-key-here&param1=value1&...
```

### 2. הגבלת קצב (Rate Limiting)
```bash
pip install Flask-Limiter
```

### 3. HTTPS בלבד
השתמש תמיד ב-HTTPS בפריסה לייצור

## מבנה קובץ ה-JSON

```json
[
  {
    "id": 1,
    "timestamp": "2024-01-23T10:30:00",
    "param1": "value1",
    "param2": "value2",
    "param3": "value3",
    "param4": "value4"
  }
]
```

## בדיקה מקומית

```bash
# הוספת נתונים
curl "http://localhost:5000/add?param1=test1&param2=test2&param3=test3&param4=test4"

# צפייה בנתונים
curl "http://localhost:5000/view"

# הורדת הקובץ
curl "http://localhost:5000/download" -o data.json
```

## טיפים

1. **גיבויים**: יש לגבות את data.json באופן קבוע
2. **ניטור**: עקוב אחר גודל הקובץ - אם יש הרבה רשומות, שקול מעבר למסד נתונים
3. **לוגים**: בדוק את הלוגים כדי לראות מי משתמש בשירות
4. **עדכון שמות**: שנה את param1-4 לשמות משמעותיים יותר בקוד

## פתרון בעיות

### השירות לא עובד על האינטרנט
- וודא שהפורט נכון (חלק מהפלטפורמות דורשות משתנה PORT)
- בדוק שה-host הוא '0.0.0.0' ולא 'localhost'

### הקובץ לא נשמר
- בדוק הרשאות כתיבה לתיקייה
- בפלטפורמות כמו Heroku, השתמש במסד נתונים חיצוני

### בעיות עם עברית
- הקובץ תומך ב-UTF-8, אבל בדוק את הקידוד ב-URL
- השתמש ב-URL encoding לתווים מיוחדים
