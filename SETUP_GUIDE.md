# GeoSense Project - Setup & Run Guide

## 📋 Prerequisites

Before starting, ensure you have the following installed:

- **Python 3.8+** (Backend)
- **Node.js 16+** and npm (Frontend)
- **MongoDB** (Database)
- **Git** (Version Control)

## 🔑 API Keys

The project uses TomTom API for geocoding and routing. The API key has been configured in the codebase:
- **TomTom API Key**: `P9qBEYuHG256dbid1aYvjznVuZNXnc5h` (already set in `backend/config.py`)

For frontend, you'll need to create a `.env` file (see Frontend Setup below).

## 🚀 Step-by-Step Setup

### 1. Clone the Repository

```bash
cd C:\updatedfolder\KatathonGeosenseProject
```

### 2. Backend Setup

#### 2.1 Navigate to Backend Directory

```bash
cd backend
```

#### 2.2 Create Virtual Environment (Windows)

```bash
python -m venv venv
```

#### 2.3 Activate Virtual Environment (Windows)

```bash
venv\Scripts\activate
```

For PowerShell:
```powershell
.\venv\Scripts\Activate.ps1
```

If you get an execution policy error, run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### 2.4 Install Backend Dependencies

```bash
pip install -r requirements.txt
```

#### 2.5 Create Environment File

Create a `.env` file in the `backend` directory:

```env
# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/geosense
MONGODB_DB_NAME=geosense

# Flask Configuration
SECRET_KEY=your-secret-key-here-change-in-production
DEBUG=True

# JWT Configuration
JWT_SECRET_KEY=your-jwt-secret-key-here
JWT_ACCESS_TOKEN_EXPIRES=604800

# TomTom API Key (already set in config.py, but you can override here)
TOMTOM_API_KEY=P9qBEYuHG256dbid1aYvjznVuZNXnc5h

# CORS
CORS_ORIGINS=http://localhost:5173

# Routing Configuration
COST_PER_KM=0.15
CO2_PER_KM_CAR=0.12
```

#### 2.6 Start MongoDB

Make sure MongoDB is running on your system:

```bash
# If MongoDB is installed as a service (Windows), it should start automatically
# Check if it's running:
net start MongoDB

# Or if using MongoDB Compass, start it from there
```

#### 2.7 Run Backend Server

```bash
python app.py
```

Or using Flask CLI:

```bash
flask run
```

The backend will start on `http://localhost:5000`

**Verify Backend is Running:**
- Open browser: `http://localhost:5000/api/routing/test`
- You should see: `{"success": true, "message": "Routing service is operational"}`

### 3. Frontend Setup

#### 3.1 Open a New Terminal/Command Prompt

Keep the backend running, and open a new terminal window.

#### 3.2 Navigate to Frontend Directory

```bash
cd C:\updatedfolder\KatathonGeosenseProject\frontend
```

#### 3.3 Install Frontend Dependencies

```bash
npm install
```

#### 3.4 Create Environment File

Create a `.env` file in the `frontend` directory:

```env
VITE_API_BASE_URL=http://localhost:5000
VITE_TOMTOM_API_KEY=P9qBEYuHG256dbid1aYvjznVuZNXnc5h
```

#### 3.5 Start Frontend Development Server

```bash
npm run dev
```

The frontend will start on `http://localhost:5173`

## 🎯 Testing the Application

### 1. Access the Application

Open your browser and go to: `http://localhost:5173`

### 2. Sign Up / Sign In

- Create a new account or sign in with existing credentials
- You'll be redirected to the dashboard after authentication

### 3. Test Route Planning with Location Names

1. Navigate to **Smart Routes** page (or from dashboard)
2. Enter location names in the input fields:
   - **Origin**: `Delhi`, `Mumbai`, `Connaught Place`, `India Gate`, etc.
   - **Destination**: `Mumbai`, `Noida`, `Times Square`, etc.
3. Click **"Find Routes"**
4. The system will:
   - Geocode the location names to lat/lon
   - Calculate 3 routes (Fastest, Eco-Friendly, Cost Efficient)
   - Display routes on the map with different colors
   - Show route comparison cards

### 4. Test Map Features

- **Route Visualization**: Three colored routes will appear on the map
  - 🔵 Blue = Fastest
  - 🟢 Green = Eco-Friendly  
  - 🟠 Orange = Cost Efficient
- **Click Route Cards**: Clicking a route card will highlight that route on the map
- **Map Filters**: Click the "Filters" button to toggle:
  - Points of Interest
  - Traffic Heatmap
  - Quiet Zones
  - Public Transport
  - Walk Friendly areas

## 🔧 Troubleshooting

### Backend Issues

**Problem: MongoDB connection error**
```
Solution: Make sure MongoDB is running
- Check: net start MongoDB
- Or start MongoDB Compass
```

**Problem: Module not found errors**
```
Solution: Make sure virtual environment is activated and dependencies are installed
- venv\Scripts\activate
- pip install -r requirements.txt
```

**Problem: Port 5000 already in use**
```
Solution: Change the port in app.py or kill the process using port 5000
- netstat -ano | findstr :5000
- taskkill /PID <PID> /F
```

### Frontend Issues

**Problem: Cannot connect to backend**
```
Solution: 
1. Check if backend is running on http://localhost:5000
2. Verify VITE_API_BASE_URL in frontend/.env
3. Check CORS settings in backend/config.py
```

**Problem: Map not loading**
```
Solution:
1. Check VITE_TOMTOM_API_KEY in frontend/.env
2. Verify API key is correct
3. Check browser console for errors
```

**Problem: Routes not displaying on map**
```
Solution:
1. Check browser console for API errors
2. Verify backend routing endpoint is working: http://localhost:5000/api/routing/test
3. Check if location names are valid (try "Delhi" to "Mumbai")
```

## 📁 Project Structure

```
KatathonGeosenseProject/
├── backend/
│   ├── app.py                 # Flask application entry point
│   ├── config.py              # Configuration (API keys, etc.)
│   ├── routes/
│   │   └── routing.py         # Routing API endpoints
│   ├── services/
│   │   ├── routing_engine.py  # Route calculation logic
│   │   └── traffic_api.py     # TomTom API integration (geocoding)
│   └── utils/
│       └── validators.py      # Input validation
│
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   └── SmartRoutes.jsx    # Main route planning page
│   │   ├── components/
│   │   │   ├── MapComponent.jsx   # Map visualization
│   │   │   └── MapFilters.jsx     # Filter controls
│   │   └── utils/
│   │       └── api.js             # API calls
│   └── package.json
│
└── SETUP_GUIDE.md             # This file
```

## 🔄 API Flow

1. **User enters location names** (e.g., "Delhi", "Mumbai")
2. **Frontend** → POST `/api/routing/compare` with `{ origin: "Delhi", destination: "Mumbai" }`
3. **Backend** → Geocodes location names using TomTom Geocoding API
4. **Backend** → Calculates 3 routes using TomTom Routing API:
   - Fastest (routeType=fastest)
   - Cheapest (routeType=shortest, avoid tolls)
   - Eco-Friendly (routeType=eco)
5. **Backend** → Returns route data with geometry (polyline coordinates)
6. **Frontend** → Displays routes on map using Leaflet
7. **User** → Can select routes, view details, use filters

## ✨ Key Features Implemented

✅ **Geocoding**: Location names → Lat/Lon conversion using TomTom API
✅ **Route Comparison**: Three route types calculated simultaneously
✅ **Map Visualization**: Routes displayed as colored polylines on interactive map
✅ **Route Selection**: Click route cards to highlight on map
✅ **Auto-zoom**: Map automatically fits all routes
✅ **Filter Controls**: Toggle POIs, Traffic Heatmap, etc.
✅ **Responsive UI**: Beautiful, modern interface with animations

## 🚀 Next Steps (Optional Enhancements)

- [ ] Implement traffic heatmap overlay using Traffic Flow API
- [ ] Add POI markers for selected categories
- [ ] Implement quiet zones detection
- [ ] Add isochrone (reachable radius) visualization
- [ ] Cache geocoded locations for faster responses
- [ ] Add route sharing functionality

## 📞 Support

If you encounter any issues:
1. Check the Troubleshooting section above
2. Review browser console and terminal logs
3. Verify all environment variables are set correctly
4. Ensure MongoDB and all services are running

---

**Happy Routing! 🗺️✨**

