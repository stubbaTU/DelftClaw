import csv
import os
_csv_data = []

def load_data(filepath: str):
    """
    Parses the CSV file and loads it into memory.
    Expects headers: name, type, link
    """
    global _csv_data
    _csv_data.clear() # Clear existing data if loaded multiple times
    
    try:
        with open(filepath, mode='r', encoding='utf-8') as file:
            # DictReader automatically uses the first row as dictionary keys
            reader = csv.DictReader(file)
            for row in reader:
                _csv_data.append(row)
    except FileNotFoundError:
        print(f"Error: The file '{filepath}' was not found.")
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")

def find_by_name(name: str) -> list:
    """
    Returns a list of items that match the given name (case-insensitive).
    """
    results = []
    for item in _csv_data:
        # Using .lower() for case-insensitive matching
        if item.get('name', '').lower() == name.lower():
            results.append(item)
    return results

def find_by_type(item_type: str) -> list:
    """
    Returns a list of items that match the given type (case-insensitive).
    """
    results = []
    for item in _csv_data:
        if item.get('type', '').lower() == item_type.lower():
            results.append(item)
    return results

def add_element(name: str, item_type: str, link: str, filepath: str):
    """
    Adds a new item to the in-memory list and appends it to the CSV file.
    """
    new_item = {'name': name, 'type': item_type, 'link': link}
    
    global _csv_data
    _csv_data.append(new_item)
    file_exists = os.path.isfile(filepath)
    
    try:
        with open(filepath, mode='a', encoding='utf-8', newline='') as file:
            fieldnames = ['name', 'type', 'link']
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            if not file_exists or os.path.getsize(filepath) == 0:
                writer.writeheader()
                
            writer.writerow(new_item)
            print(f"Successfully added '{name}' to the dataset.")
            
    except Exception as e:
        print(f"An error occurred while writing to the file: {e}")