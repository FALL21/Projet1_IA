# Projet1_IA

## Détecteur de Logiciels Malveillants

Ce projet est une application Streamlit conçue pour analyser des fichiers exécutables Windows (PE files) et déterminer s’ils contiennent des logiciels malveillants (« malware ») à l’aide d’un modèle de machine learning pré-entraîné.

---

### Fonctionnalités

- **Chargement de fichiers :** Permet aux utilisateurs de téléverser des fichiers exécutables (.exe).
- **Extraction de caractéristiques :** Analyse les informations clés du fichier (par exemple, entry point, version du linker).
- **Prédiction :** Utilise un modèle pré-entraîné pour déterminer si le fichier est malveillant.
- **Interface utilisateur :** Propose une interface simple et interactive via Streamlit.
