#Imports et Dépendances
import streamlit as st
import joblib
import pickle
import pandas as pd
import pefile
import os
import numpy as np
import struct

#Fonction de Chargement du Modèle
#Cette fonction charge un modèle de machine learning pré-entraîné et son scaler (normalisateur)
#Les chemins par défaut sont spécifiques à l'environnement de développement
def load_model(model_path='/Users/mac/Desktop/Master_AIDB_ESP/Semestre_1/IA/Projet1_IA_Mame_Bou_FALL/malware_detector.pkl', scaler_path='/Users/mac/Desktop/Master_AIDB_ESP/Semestre_1/IA/Projet1_IA_Mame_Bou_FALL/scaler.pkl'):
    """Charger le modèle et le scaler"""
    with open(model_path, 'rb') as f:
        model = joblib.load(f)
    scaler = joblib.load(scaler_path)
    return model, scaler

#Extraction des Caractéristiques
#Extrait diverses caractéristiques d'un fichier exécutable Windows (PE)
#Utilise des méthodes de secours si certains attributs sont manquants
#Inclut une gestion d'erreurs détaillée pour le débogage
def extract_features_from_executable(executable_path):
    """
    Comprehensive and robust feature extraction from executable
    """
    try:
        pe = pefile.PE(executable_path)
        
        # Safe feature extraction with multiple fallback methods
        features = {}
        
        # Entry Point
        features['AddressOfEntryPoint'] = getattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint', 0)
        
        # Linker Version - try multiple extraction methods
        try:
            # Try direct attribute access
            features['MajorLinkerVersion'] = pe.FILE_HEADER.MajorLinkerVersion
        except AttributeError:
            try:
                # Try extracting from DOS header
                features['MajorLinkerVersion'] = pe.DOS_HEADER.e_lfanew
            except AttributeError:
                # Fallback to default
                features['MajorLinkerVersion'] = 0
        
        # Image Version
        features['MajorImageVersion'] = getattr(pe.OPTIONAL_HEADER, 'MajorImageVersion', 0)
        
        # Operating System Version
        features['MajorOperatingSystemVersion'] = getattr(pe.OPTIONAL_HEADER, 'MajorOperatingSystemVersion', 0)
        
        # DLL Characteristics
        features['DllCharacteristics'] = getattr(pe.OPTIONAL_HEADER, 'DllCharacteristics', 0)
        
        # Stack Reserve Size
        features['SizeOfStackReserve'] = getattr(pe.OPTIONAL_HEADER, 'SizeOfStackReserve', 0)
        
        # Number of Sections
        features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
        
        # Resource Size
        features['ResourceSize'] = getattr(pe.OPTIONAL_HEADER, 'SizeOfInitializedData', 0)
        
        return pd.DataFrame([features])
    
    except Exception as e:
        print(f"Erreur détaillée lors de l'extraction des features : {e}")
        print(f"Type d'erreur : {type(e)}")
        
        # Additional debugging information
        try:
            print("Structure de base du fichier :")
            print(f"Taille du fichier : {os.path.getsize(executable_path)} octets")
            with open(executable_path, 'rb') as f:
                # Read first 64 bytes to check file header
                header = f.read(64)
                print("Premiers octets du fichier :", header.hex())
        except Exception as debug_e:
            print(f"Erreur during debugging : {debug_e}")
        
        return None

#Prédiction de Malware
#Normalise les caractéristiques extraites
#Effectue une prédiction binaire (malware ou non)
#Calcule la probabilité de la prédiction
def predict_malware(model, scaler, features):
    """Prédiction sur un nouvel executable"""
    features_scaled = scaler.transform(features)
    prediction = model.predict(features_scaled)
    proba = model.predict_proba(features_scaled)
    return prediction[0], proba[0]


#Fonction Principale (Interface Streamlit)
#Interface web créée avec Streamlit
#Permet de télécharger un fichier exécutable
#Analyse le fichier et détecte s'il s'agit d'un malware
#Affiche le résultat avec la probabilité
def main():
    st.title('🔍 Détecteur de Logiciels Malveillants')
    
    # Charger le modèle
    try:
        model, scaler = load_model()
    except Exception as e:
        st.error(f"Erreur de chargement du modèle : {e}")
        return

    # Upload de l'executable
    uploaded_file = st.file_uploader("Télécharger un fichier exécutable", type=['exe'])
    
    if uploaded_file is not None:
        # Sauvegarde temporaire
        with open("temp_executable", "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # Extraction des features
        features = extract_features_from_executable("temp_executable")
        
        if features is not None:
            # Prédiction
            prediction, proba = predict_malware(model, scaler, features)
            
            # Affichage des résultats
            if prediction == 1:
                st.error("⚠️ MALWARE DÉTECTÉ!")
                st.write(f"Probabilité de malware: {proba[1]*100:.2f}%")
            else:
                st.success("Fichier légitime ✅")
                st.write(f"Probabilité de malware: {proba[1]*100:.2f}%")
        
        # Suppression du fichier temporaire
        os.remove("temp_executable")

if __name__ == "__main__":
    main()