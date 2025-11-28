"""
Data preprocessing for traffic prediction
Cleans and prepares raw traffic data for ML training
"""

import pandas as pd
import numpy as np
from datetime import datetime
import os
import json

class TrafficDataPreprocessor:
    """Preprocess raw traffic data for machine learning"""
    
    def __init__(self):
        self.processed_data = None
    
    def load_raw_data(self, file_path):
        """
        Load raw data from CSV or JSON
        """
        try:
            if file_path.endswith('.csv'):
                df = pd.read_csv(file_path)
            elif file_path.endswith('.json'):
                df = pd.read_json(file_path)
            else:
                raise ValueError("Unsupported file format. Use CSV or JSON")
            
            print(f"Loaded {len(df)} records from {file_path}")
            return df
        
        except Exception as e:
            print(f"Error loading data: {e}")
            return None
    
    def clean_data(self, df):
        """
        Clean raw data:
        - Remove duplicates
        - Handle missing values
        - Remove outliers
        - Validate coordinates
        """
        print("\nCleaning data...")
        initial_rows = len(df)
        
        # Remove duplicates
        df = df.drop_duplicates()
        print(f"Removed {initial_rows - len(df)} duplicate rows")
        
        # Handle missing values
        missing_before = df.isnull().sum().sum()
        df = df.dropna()
        missing_after = df.isnull().sum().sum()
        print(f"Removed {missing_before - missing_after} missing values")
        
        # Validate coordinates (if present)
        if 'lat' in df.columns and 'lon' in df.columns:
            initial = len(df)
            df = df[(df['lat'] >= -90) & (df['lat'] <= 90)]
            df = df[(df['lon'] >= -180) & (df['lon'] <= 180)]
            print(f"Removed {initial - len(df)} rows with invalid coordinates")
        
        # Remove speed outliers (if present)
        if 'speed' in df.columns:
            initial = len(df)
            df = df[(df['speed'] >= 0) & (df['speed'] <= 200)]  # Max 200 km/h
            print(f"Removed {initial - len(df)} rows with invalid speed values")
        
        print(f"Cleaned data: {len(df)} rows remaining\n")
        return df
    
    def extract_temporal_features(self, df, timestamp_col='timestamp'):
        """
        Extract temporal features from timestamp
        - hour, day_of_week, month, is_weekend, is_peak_hour
        """
        print("Extracting temporal features...")
        
        # Convert timestamp to datetime if string
        if timestamp_col in df.columns:
            df[timestamp_col] = pd.to_datetime(df[timestamp_col])
            
            # Extract features
            df['hour'] = df[timestamp_col].dt.hour
            df['day_of_week'] = df[timestamp_col].dt.dayofweek
            df['month'] = df[timestamp_col].dt.month
            df['day_of_month'] = df[timestamp_col].dt.day
            df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
            
            # Define peak hours (7-9 AM, 5-7 PM on weekdays)
            df['is_peak_hour'] = ((df['hour'].isin([7, 8, 9, 17, 18, 19])) & 
                                  (df['is_weekend'] == 0)).astype(int)
            
            print("Temporal features extracted successfully")
        else:
            print(f"Warning: {timestamp_col} column not found")
        
        return df
    
    def calculate_congestion_level(self, df):
        """
        Calculate congestion level from speed data
        congestion_level = 1 - (current_speed / free_flow_speed)
        """
        print("Calculating congestion levels...")
        
        if 'current_speed' in df.columns and 'free_flow_speed' in df.columns:
            # Avoid division by zero
            df['free_flow_speed'] = df['free_flow_speed'].replace(0, 1)
            
            # Calculate congestion
            df['congestion_level'] = 1 - (df['current_speed'] / df['free_flow_speed'])
            
            # Clip to [0, 1] range
            df['congestion_level'] = df['congestion_level'].clip(0, 1)
            
            print("Congestion levels calculated")
        else:
            print("Warning: Speed columns not found, using default congestion levels")
            df['congestion_level'] = 0.5
        
        return df
    
    def normalize_coordinates(self, df):
        """
        Normalize coordinates to a standard range
        Useful for ML models
        """
        if 'lat' in df.columns and 'lon' in df.columns:
            print("Normalizing coordinates...")
            
            # Store original values
            df['lat_original'] = df['lat']
            df['lon_original'] = df['lon']
            
            # Normalize to [0, 1] range based on bounding box
            lat_min, lat_max = df['lat'].min(), df['lat'].max()
            lon_min, lon_max = df['lon'].min(), df['lon'].max()
            
            df['lat_normalized'] = (df['lat'] - lat_min) / (lat_max - lat_min)
            df['lon_normalized'] = (df['lon'] - lon_min) / (lon_max - lon_min)
            
            print(f"Coordinates normalized - Lat range: [{lat_min:.4f}, {lat_max:.4f}], "
                  f"Lon range: [{lon_min:.4f}, {lon_max:.4f}]")
        
        return df
    
    def add_spatial_features(self, df, center_lat=28.6139, center_lon=77.2090):
        """
        Add spatial features:
        - Distance from city center
        - Quadrant (NE, NW, SE, SW)
        """
        if 'lat' in df.columns and 'lon' in df.columns:
            print("Adding spatial features...")
            
            # Calculate distance from center (approximate)
            df['distance_from_center'] = np.sqrt(
                (df['lat'] - center_lat)**2 + (df['lon'] - center_lon)**2
            )
            
            # Determine quadrant
            df['quadrant'] = 'N/A'
            df.loc[(df['lat'] >= center_lat) & (df['lon'] >= center_lon), 'quadrant'] = 'NE'
            df.loc[(df['lat'] >= center_lat) & (df['lon'] < center_lon), 'quadrant'] = 'NW'
            df.loc[(df['lat'] < center_lat) & (df['lon'] >= center_lon), 'quadrant'] = 'SE'
            df.loc[(df['lat'] < center_lat) & (df['lon'] < center_lon), 'quadrant'] = 'SW'
            
            print("Spatial features added")
        
        return df
    
    def aggregate_by_location_time(self, df, time_window='1H'):
        """
        Aggregate data by location and time window
        Useful for reducing noise
        """
        if 'timestamp' in df.columns:
            print(f"Aggregating data by {time_window} time windows...")
            
            # Set timestamp as index
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.set_index('timestamp')
            
            # Group by location and resample
            if 'lat' in df.columns and 'lon' in df.columns:
                # Round coordinates to create location groups
                df['lat_rounded'] = df['lat'].round(3)
                df['lon_rounded'] = df['lon'].round(3)
                
                aggregated = df.groupby(['lat_rounded', 'lon_rounded']).resample(time_window).agg({
                    'current_speed': 'mean',
                    'free_flow_speed': 'mean',
                    'congestion_level': 'mean'
                }).reset_index()
                
                print(f"Aggregated to {len(aggregated)} records")
                return aggregated
        
        return df
    
    def save_processed_data(self, df, output_path):
        """Save processed data reliably to CSV (auto-creates folders)"""
        try:
            abs_path = os.path.abspath(output_path)
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)

            df.to_csv(abs_path, index=False)
            print(f"\nProcessed data saved to: {abs_path}")
            return True

        except Exception as e:
            print(f"Error saving processed data: {e}")
            return False

    
    def get_data_statistics(self, df):
        """Print data statistics"""
        print("\n" + "=" * 60)
        print("DATA STATISTICS")
        print("=" * 60)
        
        print(f"\nTotal records: {len(df)}")
        print(f"Columns: {list(df.columns)}")
        
        if 'congestion_level' in df.columns:
            print(f"\nCongestion Level Statistics:")
            print(df['congestion_level'].describe())
        
        if 'hour' in df.columns:
            print(f"\nRecords by Hour:")
            print(df['hour'].value_counts().sort_index())
        
        if 'is_weekend' in df.columns:
            weekday_count = (df['is_weekend'] == 0).sum()
            weekend_count = (df['is_weekend'] == 1).sum()
            print(f"\nWeekday records: {weekday_count}")
            print(f"Weekend records: {weekend_count}")
        
        print("=" * 60 + "\n")
    
    def preprocess_pipeline(self, input_path, output_path):
        """
        Complete preprocessing pipeline
        """
        print("=" * 60)
        print("TRAFFIC DATA PREPROCESSING PIPELINE")
        print("=" * 60 + "\n")
        
        # Load data
        df = self.load_raw_data(input_path)
        if df is None:
            return None
        
        # Clean data
        df = self.clean_data(df)
        
        # Extract features
        df = self.extract_temporal_features(df)
        df = self.calculate_congestion_level(df)
        df = self.add_spatial_features(df)
        
        # Statistics
        self.get_data_statistics(df)
        
        # Save
        self.save_processed_data(df, output_path)
        
        self.processed_data = df
        return df

def main():
    """Main preprocessing script"""
    preprocessor = TrafficDataPreprocessor()
    
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_DIR = os.path.abspath(os.path.join(BASE_DIR, "../.."))

    input_file = os.path.join(PROJECT_DIR, "data/raw/traffic_data.csv")
    output_file = os.path.join(PROJECT_DIR, "data/processed/traffic_data_processed.csv")
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"Input file not found: {input_file}")
        print("Creating sample data for demonstration...")
        
        # Create sample data
        sample_data = {
            'timestamp': pd.date_range('2024-01-01', periods=1000, freq='H'),
            'lat': np.random.uniform(28.4, 28.7, 1000),
            'lon': np.random.uniform(77.0, 77.4, 1000),
            'current_speed': np.random.uniform(20, 80, 1000),
            'free_flow_speed': np.random.uniform(60, 90, 1000)
        }
        
        df_sample = pd.DataFrame(sample_data)
        os.makedirs(os.path.dirname(input_file), exist_ok=True)
        df_sample.to_csv(input_file, index=False)
        print(f"Sample data created at: {input_file}")
    
    # Run preprocessing
    preprocessor.preprocess_pipeline(input_file, output_file)
    
    print("Preprocessing completed successfully!")

if __name__ == "__main__":
    main()