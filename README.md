# 📊 Sales & Inventory Management System — Streamlit App

This is a **Streamlit-based web application** designed to help small and medium businesses register sales, manage inventory, and generate simple reports.  
The project integrates a **PostgreSQL database**, a clean UI, and essential functionality for day-to-day operations.

---

## 🔹 Features

### ✔ **Sales registration**
- Add new sales with product, quantity, and date  
- Automatic logging into the database  
- Validation for empty fields  

### ✔ **Inventory management**
- Add, remove, or update product stock  
- Track inventory changes in real time  
- Prevent invalid operations (e.g., negative stock)

### ✔ **Dynamic reports**
- Download sales reports in PDF  
- View daily or monthly summaries  
- Visual metrics displayed directly in the UI  

### ✔ **Authentication (Optional / In Progress)**
- Basic login support  
- Session state handling  
- Logout button included  

---

## 🔹 Tech Stack

| Component     | Technology Used |
|---------------|-----------------|
| **Frontend**  | Streamlit |
| **Backend**   | Python |
| **Database**  | PostgreSQL |
| **PDF Export**| ReportLab |
| **Environment** | runtime.txt (Python 3.13) |
| **Deployment** | Streamlit Cloud |

---

## 🔹 Project Structure

```
ventas-inventario-streamlit/
│
├── .devcontainer/       # Dev container configuration
├── .gitignore
├── app.py               # Main Streamlit application
├── requirements.txt     # Python dependencies
├── runtime.txt          # Python version for deployment
└── README.md            # Project documentation
```

---

## 🔹 How to Run Locally

### **1. Clone the repository**
```bash
git clone https://github.com/renecano/ventas-inventario-streamlit.git
cd ventas-inventario-streamlit
```

### **2. Install dependencies**
```bash
pip install -r requirements.txt
```

### **3. Set up your PostgreSQL database**
Create a database and update the connection parameters in your code:
```python
db_host = "localhost"
db_user = "postgres"
db_password = "your_password"
db_name = "ventas"
```

### **4. Run the app**
```bash
streamlit run app.py
```

---

## 🔹 Deployment (Streamlit Cloud)

You can deploy this app for free using **Streamlit Cloud**:

1. Go to https://share.streamlit.io  
2. Click **New App**  
3. Select this repository  
4. Set:
   - Main file: `app.py`
   - Python version: detected automatically via `runtime.txt`
5. Deploy

---

## 🔹 Preview

This app includes:
- Clean UI with cards and buttons  
- Organized pages for Sales, Inventory, Reports  
- Automatic PDF export  
- PostgreSQL integration  

---

## 🔹 Future Improvements (Roadmap)

- Full user authentication with hashed passwords  
- Dashboard with sales trends and charts  
- Multi-branch support  
- API endpoints for mobile integration  

---

## 🔹 Author

**René Cano**  
Computer Technologies Engineering — Tecnológico de Monterrey  
Focused on innovation, data analysis, and software development.

---

⭐ If you like this project, consider giving the repo a star.
