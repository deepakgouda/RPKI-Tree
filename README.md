# RPKI-Tree

A tool for analyzing and exploring RPKI (Resource Public Key Infrastructure) certificate trees. Currently deployed at [rpki-tree.streamlit.app](https://rpki-tree.streamlit.app/).

## Features

- Load and parse RPKI certificate data
- Build hierarchical certificate trees
- Search by IP prefixes, ASNs, and SKIs
- Web interface using Streamlit

## Web Interface

The project includes a Streamlit web application for interactive exploration of the RPKI tree.

### Running the Streamlit App

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

2. Run the Streamlit app:
```bash
streamlit run app.py
```

3. Open your browser to the URL shown in the terminal (typically http://localhost:8501)

### App Features

- **Overview**: View overall statistics of the RPKI tree
- **Search Prefix**: Search for certificates containing specific IP prefixes
- **Search ASN**: Search for certificates containing specific ASNs
- **Search SKI**: Search for specific certificates by their Subject Key Identifier

All certificate links connect to the RPKI Console for detailed certificate information.

## TODO
- [ ] Add support for ROA certificates
- [ ] Mark RCs with `inherit` keyword separately
