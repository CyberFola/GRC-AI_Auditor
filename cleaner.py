import pandas as pd
from google import genai # Using the new, modern library!
import os

def clean_and_assess_data():
    print("🧹 1. Starting data cleaning...")
    df = pd.read_json('assets.json')
    df = df.drop_duplicates()
    
    df['Status'] = df['Status'].str.capitalize().replace('Actv', 'Active')
    df['MFA_Enabled'] = df['MFA_Enabled'].fillna(False)
    df['Encryption'] = df['Encryption'].fillna('Unencrypted')
    
    df.to_csv('cleaned_assets.csv', index=False)
    print("✅ Cleaning complete!")

    print("🕵️ 2. Hunting for security risks...")
    
    # Grab the API key from your computer
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("🚨 ERROR: We need a Gemini API Key to run the AI Assessor!")
        return
        
    # Initialize the modern Gemini Client
    client = genai.Client(api_key=api_key)
    risk_register = []

    for index, row in df.iterrows():
        if row['Status'] == 'Active' and (row['MFA_Enabled'] == False or row['Encryption'] in ['None', 'Unencrypted']):
            print(f"⚠️ Risk found on {row['AssetID']}! Asking AI for mitigation strategy...")
            
            prompt = f"""
            Act as a strict GRC Security Analyst. 
            We have an active asset with the following details:
            Asset ID: {row['AssetID']}
            Type: {row['Type']}
            MFA Enabled: {row['MFA_Enabled']}
            Encryption: {row['Encryption']}
            
            Write a very short, 2-sentence mitigation strategy to fix this compliance violation.
            """
            
            # Use the new generate_content syntax
            response = client.models.generate_content(
                model='gemini-2.5-flash', 
                contents=prompt
            )
            
            risk_register.append({
                "AssetID": row['AssetID'],
                "Owner": row['Owner'],
                "Vulnerability": "Missing MFA or Encryption",
                "AI_Mitigation_Plan": response.text.strip()
            })

    if risk_register:
        risk_df = pd.DataFrame(risk_register)
        risk_df.to_csv('risk_register.csv', index=False)
        print("✅ AI Assessment complete! Saved to risk_register.csv")
    else:
        print("🎉 No active risks found!")

if __name__ == "__main__":
    clean_and_assess_data()