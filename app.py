import streamlit as st
import os
import sys

sys.path.append("src")
from src.imports import *
from src.PKITree import PKITree, buildTree

# Configure Streamlit page
st.set_page_config(
    page_title="RPKI Tree Explorer",
    page_icon="🌳",
    layout="wide",
    initial_sidebar_state="expanded",
)


# Cache the tree loading to avoid reloading on every interaction
@st.cache_resource
def load_tree(curr_date):
    """Load the RPKI tree from the data file."""
    data_file = f"data/roas_{curr_date.strftime('%Y-%m-%d-00:00')}.json.gz"
    if not os.path.exists(data_file):
        data_file = f"data/roas_{curr_date.strftime('%Y-%m-%d-01:00')}.json.gz"
    if not os.path.exists(data_file):
        st.error(f"Data file {data_file} not found!")
        return None

    with st.spinner("Loading RPKI tree data..."):
        tree = buildTree(data_file)
    return tree


def create_ski_display(ski, label=None, container=None, context=""):
    """Create a SKI display with a copy button beside it."""
    if label is None:
        label = ski

    # Create unique keys with context to avoid duplicates
    # copy_button_key = (
    #     f"copy_btn_{hash(ski)}_{hash(label)}_{hash(context)}_{id(container)}"
    # )

    # Use the provided container or default to st
    ctx = container if container else st
    ctx.code(f"\n{ski}\n")

    # # Create columns to limit width - adjust the ratio as needed
    # width = 0.21
    # col1, col2 = ctx.columns(
    #     [width, 1 - width]
    # )  # width% for code, (1-width)% empty space

    # with col1:
    #     st.code(f"\n{ski}\n", language=None)


def display_ski_info(tree, ski, context_prefix=""):
    """Display detailed information about a certificate SKI."""
    data = tree.get_data(ski)
    if not data:
        st.error(f"No data found for SKI: {ski}")
        return

    # Display basic certificate info
    st.subheader("Certificate Information")

    col1, col2 = st.columns(2)

    with col1:
        st.write(f"**SKI:** `{ski}`")
        st.write(f"**Type:** `{data.get('type', 'Unknown')}`")
        if "tal" in data:
            st.write(f"**TAL:** `{data['tal'].upper()}`")

        # Show CA domain
        try:
            domain = tree.get_ca_domain(ski)
            st.write(f"**CA Domain:** `{domain}`")
        except:
            st.write("**CA Domain:** Not available")

        # Show RPKI Console URL
        url = tree.get_url(ski)
        if url:
            st.markdown(f"**RPKI Console Link:** [{ski}]({url})")
        else:
            st.write(f"**RPKI Console Link:** `{ski}`")

    with col2:
        # Show parent
        parent = tree.get_parent(ski)
        if parent and len(parent) > 0:
            st.write("**Parent:**")
            create_ski_display(parent, context=f"{context_prefix}_parent")
        else:
            st.write("**Parent:** Root certificate")

    # Show children with truncation
    children = tree.get_children(ski)
    if children:
        st.subheader(f"Children ({len(children)} total)")

        if len(children) > 10:
            st.warning(
                f"This certificate has {len(children)} children. Showing first 10 only."
            )
            # st.info(
            #     "💡 Use the parent-child search below to find specific certificates."
            # )
            displayed_children = children[:10]
        else:
            displayed_children = children

        # Display children in columns for better layout
        for idx, child_ski in enumerate(displayed_children):
            create_ski_display(child_ski, context=f"{context_prefix}_child_{idx}")
    else:
        st.write("**Children:** None (End entity)")

    # Show certificate resources
    st.subheader("Certificate Resources")

    # Get resources from the certificate data
    ipv4_resources = []
    ipv6_resources = []
    asn_resources = []

    if ski in tree.resource_dict_pfx_v4:
        for ip in tree.resource_dict_pfx_v4[ski]:
            ipv4_resources.append(ip)
    if ski in tree.resource_dict_pfx_v6:
        for ip in tree.resource_dict_pfx_v6[ski]:
            ipv6_resources.append(ip)
    if ski in tree.resource_dict_asn:
        for asn in tree.resource_dict_asn[ski]:
            asn_resources.append(str(asn))

    # Display resources in columns
    col1, col2, col3 = st.columns(3)

    with col1:
        st.write("**IPv4 Prefixes:**")
        if ipv4_resources:
            if len(ipv4_resources) > 10:
                st.write(f"Showing 10 of {len(ipv4_resources)} prefixes:")
                for prefix in ipv4_resources[:10]:
                    st.code(prefix, language="text")
                st.info(f"... and {len(ipv4_resources) - 10} more IPv4 prefixes")
            else:
                for prefix in ipv4_resources:
                    st.code(prefix, language="text")
        else:
            st.write("None")

    with col2:
        st.write("**IPv6 Prefixes:**")
        if ipv6_resources:
            if len(ipv6_resources) > 10:
                st.write(f"Showing 10 of {len(ipv6_resources)} prefixes:")
                for prefix in ipv6_resources[:10]:
                    st.code(prefix, language="text")
                st.info(f"... and {len(ipv6_resources) - 10} more IPv6 prefixes")
            else:
                for prefix in ipv6_resources:
                    st.code(prefix, language="text")
        else:
            st.write("None")

    with col3:
        st.write("**ASNs:**")
        if asn_resources:
            if len(asn_resources) > 10:
                st.write(f"Showing 10 of {len(asn_resources)} ASNs:")
                for asn in asn_resources[:10]:
                    st.code(asn, language="text")
                st.info(f"... and {len(asn_resources) - 10} more ASNs")
            else:
                for asn in asn_resources:
                    st.code(asn, language="text")
        else:
            st.write("None")


def get_tree_statistics(tree):
    """Generate overall statistics for the tree."""
    stats = {}

    # Count different types of certificates
    ca_certs = 0
    roas = 0
    roots = 0

    for ski, data in tree.node_data.items():
        if data.get("type") == "ca_cert":
            ca_certs += 1
        elif data.get("type") == "roa":
            roas += 1
        if "tal" in data:
            roots += 1

    stats["total_certificates"] = len(tree.node_data)
    stats["ca_certificates"] = ca_certs
    stats["roas"] = roas
    stats["root_certificates"] = roots
    stats["rir_roots"] = tree.get_root_dict()

    return stats


def main():
    """Main Streamlit application."""
    # curr_date = datetime.datetime(2023, 11, 2)
    curr_date = datetime.datetime(2025, 10, 1)
    st.title("🌳 RPKI Tree Explorer")
    st.markdown(f"**Data Date:** {curr_date.strftime('%B %d, %Y')}")

    # Load the tree
    tree = load_tree(curr_date)
    if tree is None:
        st.error("Failed to load RPKI tree data.")
        return

    # Create tabs for navigation
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        [
            "📊 Overview",
            "🔍 Search Prefix",
            "🔢 Search ASN",
            "🔑 Search SKI",
            "🔗 Parent-Child Search",
        ]
    )

    with tab1:
        st.header("RPKI Tree Statistics")

        # Get and display statistics
        stats = get_tree_statistics(tree)

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Certificates", stats["total_certificates"])
        with col2:
            st.metric("CA Certificates", stats["ca_certificates"])
        with col3:
            st.metric("ROAs", stats["roas"])
        with col4:
            st.metric("Root Certificates", stats["root_certificates"])

        # Display RIR roots
        st.subheader("Regional Internet Registry (RIR) Roots")
        for rir, ski in stats["rir_roots"].items():
            col1, col2 = st.columns([1, 4])
            with col1:
                st.write(f"**{rir}:**")
            with col2:
                create_ski_display(ski, context=f"rir_{rir}")

    with tab2:
        st.header("🔍 Search IP Prefix")
        st.markdown("Search for certificates that contain a specific IP prefix.")

        prefix = st.text_input(
            "Enter IP Prefix (e.g., 192.168.1.0/24, 2001:db8::/32):",
            placeholder="192.168.1.0/24",
        )

        if prefix:
            try:
                with st.spinner("Searching for prefix..."):
                    results = tree.search_prefix(prefix)

                if results:
                    st.success(
                        f"Found {len(results)} certificate(s) containing prefix `{prefix}`"
                    )

                    for idx, ski in enumerate(results):
                        with st.expander(f"Certificate: {ski}"):
                            display_ski_info(tree, ski, f"prefix_search_{idx}")
                else:
                    st.warning(f"No certificates found containing prefix `{prefix}`")

            except Exception as e:
                st.error(f"Error searching for prefix: {str(e)}")

    with tab3:
        st.header("🔍 Search ASN")
        st.markdown(
            "Search for certificates that contain a specific Autonomous System Number."
        )

        asn_input = st.text_input("Enter ASN (e.g., 65001):", placeholder="65001")

        if asn_input:
            try:
                asn = int(asn_input)

                with st.spinner("Searching for ASN..."):
                    results = tree.search_asn(asn)

                if results:
                    st.success(
                        f"Found {len(results)} certificate(s) containing ASN `{asn}`"
                    )

                    for idx, ski in enumerate(results):
                        with st.expander(f"Certificate: {ski}"):
                            display_ski_info(tree, ski, f"asn_search_{idx}")
                else:
                    st.warning(f"No certificates found containing ASN `{asn}`")

            except ValueError:
                st.error("Please enter a valid ASN number")
            except Exception as e:
                st.error(f"Error searching for ASN: {str(e)}")

    with tab4:
        st.header("🔍 Search SKI")
        st.markdown("Search for a specific certificate by its Subject Key Identifier.")

        ski = st.text_input(
            "Enter SKI:",
            placeholder="Enter full or partial SKI (with or without colons)...",
        )

        if ski:
            # Normalize the search term by removing colons and converting to lowercase
            normalized_search = ski.replace(":", "").lower()

            # Function to normalize SKI for comparison
            def normalize_ski(ski_str):
                return ski_str.replace(":", "").lower()

            # Check for exact match (try both original and normalized)
            exact_match = None
            if ski in tree.node_data:
                exact_match = ski
            else:
                # Look for exact match with normalized comparison
                for tree_ski in tree.node_data.keys():
                    if normalize_ski(tree_ski) == normalized_search:
                        exact_match = tree_ski
                        break

            if exact_match:
                st.success(f"Found exact match: `{exact_match}`")
                display_ski_info(tree, exact_match, "exact_match")
            else:
                # Search for partial matches using normalized comparison
                matches = []
                for tree_ski in tree.node_data.keys():
                    # Check if normalized search term is in normalized tree SKI
                    if normalized_search in normalize_ski(tree_ski):
                        matches.append(tree_ski)

                if matches:
                    st.info(f"Found {len(matches)} partial match(es)")

                    if len(matches) > 10:
                        st.warning("Too many matches. Showing first 10 results.")
                        matches = matches[:10]

                    for match_ski in matches:
                        with st.expander(f"Certificate: {match_ski}"):
                            display_ski_info(
                                tree, match_ski, f"search_result_{hash(match_ski)}"
                            )
                else:
                    st.warning(f"No certificates found with SKI containing `{ski}`")

        # Footer with help information
        # st.divider()
        # st.info(
        #     "💡 You can search with or without colons (e.g., 'A1:B2:C3' or 'A1B2C3')"
        # )

    with tab5:
        st.header("🔍 Parent-Child Relationship Search")
        st.markdown("Search for parent-child relationships between certificates.")

        # Two main search types
        search_type = st.radio(
            "Search Type:",
            ["Check if certificate is child of another", "Find parent of certificate"],
        )

        if search_type == "Check if certificate is child of another":
            st.subheader("Check Parent-Child Relationship")
            # st.info("💡 You can enter SKIs with or without colons")

            col1, col2 = st.columns(2)

            with col1:
                parent_ski_input = st.text_input(
                    "Parent SKI:", placeholder="Enter parent SKI..."
                )

            with col2:
                child_ski_input = st.text_input(
                    "Child SKI:", placeholder="Enter child SKI..."
                )

            if parent_ski_input and child_ski_input:
                # Function to find actual SKI from input (with or without colons)
                def find_actual_ski(input_ski):
                    # First try exact match
                    if input_ski in tree.node_data:
                        return input_ski

                    # Try normalized match
                    normalized_input = input_ski.replace(":", "").lower()
                    for tree_ski in tree.node_data.keys():
                        if tree_ski.replace(":", "").lower() == normalized_input:
                            return tree_ski
                    return None

                parent_ski = find_actual_ski(parent_ski_input)
                child_ski = find_actual_ski(child_ski_input)

                if not parent_ski:
                    st.error(f"Parent SKI `{parent_ski_input}` not found in tree")
                elif not child_ski:
                    st.error(f"Child SKI `{child_ski_input}` not found in tree")
                else:
                    # Check if child_ski is in the children of parent_ski
                    children = tree.get_children(parent_ski)

                    if children and child_ski in children:
                        st.success(f"✅ `{child_ski}` IS a child of `{parent_ski}`")

                        # Show both certificates
                        col1, col2 = st.columns(2)

                        with col1:
                            st.subheader("Parent Certificate")
                            display_ski_info(tree, parent_ski, "parent_child_parent")

                        with col2:
                            st.subheader("Child Certificate")
                            display_ski_info(tree, child_ski, "parent_child_child")

                    else:
                        st.error(f"❌ `{child_ski}` is NOT a child of `{parent_ski}`")

        else:  # Find parent of certificate
            st.subheader("Find Parent Certificate")
            # st.info("💡 You can enter SKI with or without colons")

            target_ski_input = st.text_input(
                "Certificate SKI:", placeholder="Enter SKI to find its parent..."
            )

            if target_ski_input:
                # Function to find actual SKI from input (with or without colons)
                def find_actual_ski(input_ski):
                    # First try exact match
                    if input_ski in tree.node_data:
                        return input_ski

                    # Try normalized match
                    normalized_input = input_ski.replace(":", "").lower()
                    for tree_ski in tree.node_data.keys():
                        if tree_ski.replace(":", "").lower() == normalized_input:
                            return tree_ski
                    return None

                target_ski = find_actual_ski(target_ski_input)

                if target_ski:
                    parent = tree.get_parent(target_ski)

                    if parent and len(parent) > 0:
                        st.success(f"Parent found: `{parent}`")

                        st.subheader("Parent Certificate")
                        display_ski_info(tree, parent, "find_parent_parent")
                    else:
                        st.info(
                            f"Certificate `{target_ski}` is a root certificate (no parent)"
                        )
                        display_ski_info(tree, target_ski, "find_parent_root")
                else:
                    st.error(f"Certificate with SKI `{target_ski_input}` not found")

        # Additional feature: Show certificate path
        st.subheader("Certificate Path to Root")
        # st.info("💡 You can enter SKI with or without colons")
        path_ski_input = st.text_input(
            "SKI for path trace:", placeholder="Enter SKI to trace path to root..."
        )

        if path_ski_input:
            # Function to find actual SKI from input (with or without colons)
            def find_actual_ski(input_ski):
                # First try exact match
                if input_ski in tree.node_data:
                    return input_ski

                # Try normalized match
                normalized_input = input_ski.replace(":", "").lower()
                for tree_ski in tree.node_data.keys():
                    if tree_ski.replace(":", "").lower() == normalized_input:
                        return tree_ski
                return None

            path_ski = find_actual_ski(path_ski_input)

            if path_ski:
                path = tree.get_path(path_ski)

                if path:
                    path = path[::-1]  # Reverse to go from root to leaf
                    st.success(f"Path from root to `{path_ski}`:")

                    for i, ski in enumerate(path):
                        # Use columns to create indentation effect
                        cols = st.columns([i + 1, 10])
                        with cols[1]:
                            st.write(f"↘️ Level {i}:")
                            create_ski_display(ski, context=f"path_{i}")
                else:
                    st.warning("Could not trace path for this certificate")
            else:
                st.error(f"Certificate with SKI `{path_ski_input}` not found")


if __name__ == "__main__":
    main()
