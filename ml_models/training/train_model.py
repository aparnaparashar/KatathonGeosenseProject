"""
Traffic Prediction Model Training
Trains ML model to predict traffic congestion levels
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, r2_score, mean_absolute_error
import joblib
import os
from datetime import datetime
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

class TrafficModelTrainer:
    """Train and evaluate traffic prediction models"""
    
    def __init__(self, data_path=None):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = ['hour', 'day_of_week', 'lat', 'lon', 'is_weekend', 'is_peak_hour']
        self.target_column = 'congestion_level'
        
        if data_path:
            self.data = self.load_data(data_path)
        else:
            self.data = self.generate_synthetic_data()
    
    def load_data(self, data_path):
        """Load training data from CSV"""
        try:
            df = pd.read_csv(data_path)
            print(f"Loaded {len(df)} records from {data_path}")
            return df
        except Exception as e:
            print(f"Error loading data: {e}")
            print("Generating synthetic data instead...")
            return self.generate_synthetic_data()
    
    def generate_synthetic_data(self, n_samples=10000):
        """
        Generate synthetic traffic data for training
        This simulates realistic traffic patterns
        """
        print(f"Generating {n_samples} synthetic training samples...")
        
        np.random.seed(42)
        
        data = []
        
        for _ in range(n_samples):
            hour = np.random.randint(0, 24)
            day_of_week = np.random.randint(0, 7)
            lat = np.random.uniform(28.4, 28.7)  # Delhi area
            lon = np.random.uniform(77.0, 77.4)
            
            is_weekend = 1 if day_of_week >= 5 else 0
            is_peak_hour = 1 if (7 <= hour <= 9 or 17 <= hour <= 19) and not is_weekend else 0
            
            # Generate realistic congestion levels
            base_congestion = 0.3
            
            # Peak hours increase congestion
            if is_peak_hour:
                base_congestion += 0.4
            
            # Weekdays have more traffic
            if not is_weekend:
                base_congestion += 0.2
            
            # Late night has less traffic
            if 22 <= hour or hour <= 5:
                base_congestion -= 0.2
            
            # Add some randomness
            congestion_level = np.clip(base_congestion + np.random.normal(0, 0.1), 0, 1)
            
            data.append({
                'hour': hour,
                'day_of_week': day_of_week,
                'lat': lat,
                'lon': lon,
                'is_weekend': is_weekend,
                'is_peak_hour': is_peak_hour,
                'congestion_level': congestion_level
            })
        
        df = pd.DataFrame(data)
        print("Synthetic data generated successfully")
        return df
    
    def prepare_features(self):
        """Prepare features and target for training"""
        X = self.data[self.feature_columns]
        y = self.data[self.target_column]
        
        return X, y
    
    def train(self, model_type='random_forest', test_size=0.2):
        """
        Train the model
        
        model_type: 'random_forest' or 'gradient_boosting'
        test_size: proportion of data for testing
        """
        print(f"\nTraining {model_type} model...")
        
        # Prepare data
        X, y = self.prepare_features()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42
        )
        
        print(f"Training set: {len(X_train)} samples")
        print(f"Test set: {len(X_test)} samples")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Choose model
        if model_type == 'random_forest':
            self.model = RandomForestRegressor(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
        elif model_type == 'gradient_boosting':
            self.model = GradientBoostingRegressor(
                n_estimators=100,
                max_depth=5,
                learning_rate=0.1,
                random_state=42
            )
        else:
            raise ValueError(f"Unknown model type: {model_type}")
        
        # Train model
        print("Training in progress...")
        self.model.fit(X_train_scaled, y_train)
        print("Training completed!")
        
        # Evaluate
        print("\nEvaluating model...")
        train_predictions = self.model.predict(X_train_scaled)
        test_predictions = self.model.predict(X_test_scaled)
        
        # Calculate metrics
        train_mse = mean_squared_error(y_train, train_predictions)
        test_mse = mean_squared_error(y_test, test_predictions)
        train_mae = mean_absolute_error(y_train, train_predictions)
        test_mae = mean_absolute_error(y_test, test_predictions)
        train_r2 = r2_score(y_train, train_predictions)
        test_r2 = r2_score(y_test, test_predictions)
        
        print("\n=== MODEL PERFORMANCE ===")
        print(f"Training MSE: {train_mse:.4f}")
        print(f"Test MSE: {test_mse:.4f}")
        print(f"Training MAE: {train_mae:.4f}")
        print(f"Test MAE: {test_mae:.4f}")
        print(f"Training R²: {train_r2:.4f}")
        print(f"Test R²: {test_r2:.4f}")
        
        # Feature importance
        if hasattr(self.model, 'feature_importances_'):
            print("\n=== FEATURE IMPORTANCE ===")
            importance = pd.DataFrame({
                'feature': self.feature_columns,
                'importance': self.model.feature_importances_
            }).sort_values('importance', ascending=False)
            print(importance.to_string(index=False))
        
        return {
            'train_mse': train_mse,
            'test_mse': test_mse,
            'train_r2': train_r2,
            'test_r2': test_r2
        }
    
    def save_model(self, output_dir=None):
        """Save trained core model + scaler safely with unique naming"""
        import os, joblib
        from datetime import datetime

        # ml_models/training/train_model.py → go to project root
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        PROJECT_DIR = os.path.abspath(os.path.join(BASE_DIR, "../.."))

        # Save inside core_models/
        model_dir = os.path.join(PROJECT_DIR, "ml_models/saved_models/core_models")
        if output_dir:
            model_dir = output_dir

        os.makedirs(model_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Timestamped files
        model_ts = os.path.join(model_dir, f"traffic_rf_core_{timestamp}.pkl")
        scaler_ts = os.path.join(model_dir, f"traffic_scaler_core_{timestamp}.pkl")

        # Default filenames
        model_default = os.path.join(model_dir, "traffic_rf_core.pkl")
        scaler_default = os.path.join(model_dir, "traffic_scaler_core.pkl")

        # Save all versions
        joblib.dump(self.model, model_ts)
        joblib.dump(self.scaler, scaler_ts)
        joblib.dump(self.model, model_default)
        joblib.dump(self.scaler, scaler_default)

        print("\n=== CORE MODEL SAVED ===")
        print(model_ts)
        print(scaler_ts)
        print(model_default)
        print(scaler_default)

        return model_ts

    
    def predict_sample(self, hour, day_of_week, lat, lon):
        """Make a sample prediction"""
        is_weekend = 1 if day_of_week >= 5 else 0
        is_peak_hour = 1 if (7 <= hour <= 9 or 17 <= hour <= 19) and not is_weekend else 0
        
        features = np.array([[hour, day_of_week, lat, lon, is_weekend, is_peak_hour]])
        features_scaled = self.scaler.transform(features)
        
        prediction = self.model.predict(features_scaled)[0]
        
        return prediction

def main():
    """Main training pipeline"""
    print("=" * 60)
    print("GeoSense Traffic Prediction Model Training")
    print("=" * 60)
    
    # Initialize trainer
    trainer = TrafficModelTrainer()
    
    # Train model
    metrics = trainer.train(model_type='random_forest')
    
    # Save model
    model_path = trainer.save_model()
    
    # Test predictions
    print("\n=== SAMPLE PREDICTIONS ===")
    test_cases = [
        (8, 1, 28.6139, 77.2090, "Monday 8 AM (Peak Hour)"),
        (14, 1, 28.6139, 77.2090, "Monday 2 PM"),
        (23, 1, 28.6139, 77.2090, "Monday 11 PM (Late Night)"),
        (10, 6, 28.6139, 77.2090, "Sunday 10 AM (Weekend)")
    ]
    
    for hour, day, lat, lon, description in test_cases:
        prediction = trainer.predict_sample(hour, day, lat, lon)
        congestion = 'Low' if prediction < 0.3 else 'Moderate' if prediction < 0.6 else 'High' if prediction < 0.8 else 'Severe'
        print(f"{description}: {prediction:.3f} ({congestion})")
    
    print("\n" + "=" * 60)
    print("Training completed successfully!")
    print("=" * 60)

if __name__ == "__main__":
    main()
    

