from src.imports import *

MAX_ASN_NUM = 4294967295


class PKITree:
    """
    A class representing a Public Key Infrastructure (PKI) tree structure.

    This class implements a tree-like structure to represent the hierarchical
    relationships between PKI certificates, particularly useful for modeling
    Resource Public Key Infrastructure (RPKI) structures.

    Attributes:
        parent_to_child (defaultdict): Maps parent SKIs to lists of child SKIs.
        child_to_parent (defaultdict): Maps child SKIs to their parent SKI.
        node_data (dict): Stores additional data associated with each node (SKI).
        resource_dict_pfx_v4 (dict): Maps SKIs to PyTricia objects for IPv4 prefixes.
        resource_dict_pfx_v6 (dict): Maps SKIs to PyTricia objects for IPv6 prefixes.
        resource_dict_asn (dict): Maps SKIs to sets of ASNs.

    Methods:
        __init__(): Initializes an empty PKITree.
        __str__(): Returns a string representation of the tree's root list.
        insert_node(ski, aki, data): Inserts a new node into the tree.
        get_parent(ski): Retrieves the parent SKI of a given node.
        get_children(ski): Retrieves the list of child SKIs for a given node.
        get_data(ski): Retrieves the data associated with a given node.
        get_url(ski): Constructs and returns a URL for a given node.
        get_ca_domain(ski): Extracts and returns the CA domain for a given node.
        get_path(ski, delim): Returns the path from root to the given node.
        get_root_dict(): Returns a list of all root nodes in the tree.
        get_resource_list(root, resource_type, recursive): Retrieves resources (IP prefixes and ASNs) from the tree.
        populate_resources(): Populates the resource dictionaries for IPv4 and IPv6 prefixes and ASNs.
        is_resource_certificate(ski): Checks if a given certificate is a resource certificate.
        is_roa(ski): Checks if a given certificate is a ROA certificate.
        search_asn(asn, resource_type): Searches the tree for a given ASN.
        search_prefix(prefix, resource_type): Searches the tree for a given IP prefix.
    """

    def __init__(self) -> None:
        """
        Initializes an empty PKITree.
        """
        self.parent_to_child = defaultdict(list)
        self.child_to_parent = defaultdict(str)
        self.node_data = {}
        self.resource_dict_pfx_v4 = {}
        self.resource_dict_pfx_v6 = {}
        self.resource_dict_asn = {}

    def __str__(self) -> str:
        """
        Returns a string representation of the tree's root list.

        Returns:
            str: A pipe-separated string of root SKIs.
        """
        return "|".join(self.get_root_dict())

    def insert_node(self, ski: str, aki: str, data: json) -> None:
        """
        Inserts a new node into the tree.

        Args:
            ski (str): Subject Key Identifier of the node.
            aki (str): Authority Key Identifier of the node's parent.
            data (dict): Additional data associated with the node.
        """
        if ski in self.node_data:
            logger.warning(f"Node with SKI {ski} already exists")
            return
        self.node_data[ski] = data
        if ski != aki:
            self.parent_to_child[aki].append(ski)
        if len(self.child_to_parent[ski]) > 0:
            logger.warning(f"Node with SKI {ski} already exists")
            return
        if ski == aki:
            logger.warning(f"Node with SKI {ski} is its own parent")
            aki = ""
        self.child_to_parent[ski] = aki

        if aki not in self.child_to_parent:
            self.child_to_parent[aki] = ""

    def get_parent(self, ski: str) -> str:
        """
        Retrieves the parent SKI of a given node.

        Args:
            ski (str): The SKI of the node.

        Returns:
            str: The SKI of the parent node, or None if not found.
        """
        return self.child_to_parent.get(ski, None)

    def get_children(self, ski: str) -> str:
        """
        Retrieves the list of child SKIs for a given node.

        Args:
            ski (str): The SKI of the parent node.

        Returns:
            list: A list of child SKIs, or None if no children found.
        """
        return self.parent_to_child.get(ski, None)

    def get_data(self, ski: str) -> str:
        """
        Retrieves the data associated with a given node.

        Args:
            ski (str): The SKI of the node.

        Returns:
            dict: The data associated with the node, or None if not found.
        """
        return self.node_data.get(ski, None)

    def get_url(self, ski: str) -> str:
        """
        Constructs and returns a URL for a given node.

        Args:
            ski (str): The SKI of the node.

        Returns:
            str: A URL string, or None if the node data is not found.
        """
        data = self.get_data(ski)
        if data is None:
            return None
        url = data["file"]
        return f"https://console.rpki-client.org/{url}.html"

    def get_ca_domain(self, ski: str) -> str:
        """
        Extracts and returns the CA domain for a given node.

        Args:
            ski (str): The SKI of the node.

        Returns:
            str: The CA domain string.
        """
        data = self.get_data(ski)
        if "carepository" in data:
            url = data["carepository"]
        else:
            url = data["file"]
        url = url.replace("rsync://", "")
        return url.split("/")[0]

    def get_path(self, ski: str) -> list:
        """
        Returns the path from given node to the parent.

        Args:
            ski (str): The SKI of the target node.

        Returns:
            list: A list of SKIs from the target node to the root.
        """
        path_list = []
        while len(ski) > 0:
            path_list.append(ski)
            parent = self.get_parent(ski)
            if parent == ski:
                break
            ski = parent
        return path_list

    def get_root_dict(self) -> dict:
        """
        Returns a dict of all root nodes in the tree.

        Returns:
            dict: A dict of RIR and SKIs of root nodes.
        """
        root_dict = {}
        for ski, data in self.node_data.items():
            if "tal" in data:
                if len(ski) > 0:
                    root_dict[data["tal"].upper()] = ski
        return root_dict

    def get_resource_list(
        self, root: str, resource_type: str = "all", recursive=True
    ) -> list:
        """
        Retrieves resources (IP prefixes and ASNs) from the tree.

        Args:
            root (str): The SKI of the root node to start the search from.
            resource_type (str, optional): Type of resources to retrieve. Defaults to "all".
            recursive (bool, optional): Whether to search recursively. Defaults to True.

        Returns:
            tuple: A tuple containing PyTricia objects for IPv4 and IPv6 prefixes, and a list of ASNs.
        """
        ctr = 0
        pyt4 = PyTricia()
        pyt6 = PyTricia(128)
        asn_list = []
        queue = []
        children = self.get_children(root)
        queue.append(root)
        if recursive:
            if children is not None:
                queue.extend(children.copy())

        def extract_resources(resource_list) -> Tuple[PyTricia, PyTricia]:
            prefix_list = []
            asn_list = []
            for resource in resource_list:
                for k, v in resource.items():
                    if k in ["asid_inherit", "ip_inherit"]:
                        continue
                    if k == "ip_prefix":
                        prefix_list.append(v)
                    elif k == "asid":
                        asn_list.append(v)
                    elif k == "ip_range":
                        start_ip, end_ip = v["min"], v["max"]
                        prefix_list.extend(get_cidr(start_ip, end_ip))
                    elif k == "asrange":
                        start_asn, end_asn = v["min"], v["max"]
                        if end_asn == MAX_ASN_NUM:
                            logger.warning(f"Large ASN range: {start_asn} - {end_asn}")
                        else:
                            asn_list.extend([x for x in range(start_asn, end_asn + 1)])
                        pass
                    else:
                        print(resource)
            return prefix_list, asn_list

        def extract_vrps(vrps) -> Tuple[List[str], List[int]]:
            prefix_list = []
            origin_asn_list = []
            for vrp in vrps:
                prefix_list.append(vrp["prefix"])
                asn_list.append(vrp["asid"])
            return prefix_list, origin_asn_list

        while len(queue) > 0:
            child = queue.pop(0)
            ctr += 1

            curr_pfx_list = []

            data = self.get_data(child).copy()
            if data is None:
                # logger.warning(f"No data found for {child}")
                continue
            if data["type"] == "roa":
                if resource_type == "ca_cert":
                    continue
                curr_pfx_list, curr_asn_list = extract_vrps(data["vrps"])
            elif data["type"] == "ca_cert":
                if resource_type == "roa":
                    continue
                curr_pfx_list, curr_asn_list = extract_resources(
                    data["subordinate_resources"]
                )
            else:
                logger.warning(f"Unhandled resource type : {data['type']}")

            for pfx in curr_pfx_list:
                if (pfx == "0.0.0.0/0") or (pfx == "::/0"):
                    continue
                if ":" in pfx:
                    pyt6[pfx] = child
                else:
                    pyt4[pfx] = child
            asn_list.extend(curr_asn_list)
            if recursive:
                children = self.get_children(child)
                if children is not None:
                    if len(children) > 0:
                        queue.extend(children)
        return pyt4, pyt6, set(asn_list)

    def populate_resources(self) -> None:
        """
        Populates the resource dictionaries for IPv4 and IPv6 prefixes and ASNs.
        """
        for node in self.node_data.keys():
            if self.is_roa(node):
                continue
            if self.is_rir_owned_rc(node):
                continue
            pyt4, pyt6, asn_list = self.get_resource_list(node, recursive=False)
            self.resource_dict_pfx_v4[node] = pyt4
            self.resource_dict_pfx_v6[node] = pyt6
            self.resource_dict_asn[node] = set(asn_list)

    def is_rir_owned_rc(self, ski: str) -> bool:
        data = self.get_data(ski)
        if data is None:
            return None
        if "tal" in data:
            return True
        if self.is_roa(ski):
            return False
        hit_list = [
            {"asrange": {"min": 0, "max": 4294967295}},
            {"asrange": {"min": 1, "max": 4294967295}},
            {"ip_prefix": "0.0.0.0/0"},
            {"ip_prefix": "::/0"},
            {"asid_inherit": True},
            {"ip_inherit": True},
            {"ip_inherit": True},
        ]
        for hit in hit_list:
            if hit in data["subordinate_resources"]:
                return True
        return False

    def is_end_node_certificate(self, ski: str) -> bool:
        """
        Determines if the given Subject Key Identifier (SKI) corresponds to an end node certificate.

        Args:
            ski (str): The Subject Key Identifier of the certificate to check.

        Returns:
            bool: True if the SKI corresponds to an end node certificate, False otherwise.
        """
        data = self.get_data(ski)
        if data is None:
            return None

        if self.is_roa(ski):
            return False

        child_list = self.get_children(ski)
        # If RC has no children, consider it an end-node
        if child_list is None:
            return True

        # If all the children are ROAs, consider it an end-node
        for child in child_list:
            child_data = self.get_data(child)
            if child_data["type"] != "roa":
                return False
        return True

    def has_issued_roas(self, ski: str) -> bool:
        """
        Determines if the given Subject Key Identifier (SKI) has issued ROAs.

        Args:
            ski (str): The Subject Key Identifier of the certificate to check.

        Returns:
            bool: True if the SKI has issued ROAs, False otherwise.
        """
        data = self.get_data(ski)
        if data is None:
            return None
        if data["type"] != "ca_cert":
            return False
        if self.is_rir_owned_rc(ski):
            return False
        child_list = self.get_children(ski)
        if child_list is None:
            return True
        for child in child_list:
            child_data = self.get_data(child)
            if child_data["type"] == "roa":
                return True
        return False

    def is_roa(self, ski: str) -> bool:
        """
        Checks if a given certificate is a ROA certificate.

        Args:
            ski (str): The SKI of the certificate.

        Returns:
            bool: True if the certificate is a ROA certificate, None, if no data available, False otherwise.
        """
        data = self.get_data(ski)
        if data is None:
            return None
        if data["type"] == "roa":
            return True
        return False

    def search_asn(self, asn: int, resource_type: str = "all") -> list:
        """
        Searches the tree for a given ASN.

        Args:
            asn (int): The ASN to search for.
            resource_type (str, optional): Type of resources to retrieve. Defaults to "all".

        Returns:
            list: The list of SKIs of the nodes containing the ASN.
        """
        res_list = []
        if type(asn) == str:
            asn = asn.replace("AS", "")
            asn = int(asn)
        for node, asn_set in self.resource_dict_asn.items():
            if asn in asn_set:
                if resource_type == "all":
                    res_list.append(node)
                else:
                    data = self.get_data(node)
                    if data["type"] == resource_type:
                        res_list.append(node)
        return res_list

    def search_prefix(self, prefix: str, resource_type: str = "all") -> list:
        """
        Searches the tree for a given IP prefix.

        Args:
            prefix (str): The IP prefix to search for.
            resource_type (str, optional): Type of resources to retrieve. Defaults to "all".

        Returns:
            list: The list of SKIs of the nodes containing the prefix.
        """
        res_list = []
        if ":" in prefix:
            curr_resource_dict_pfx = self.resource_dict_pfx_v6
        else:
            curr_resource_dict_pfx = self.resource_dict_pfx_v4
        for node, pyt in curr_resource_dict_pfx.items():
            if pyt is None:
                continue
            if prefix in pyt:
                if resource_type == "all":
                    res_list.append(node)
                else:
                    data = self.get_data(node)
                    if data["type"] == resource_type:
                        res_list.append(node)
        return res_list


def load_rpki_archive(file_path) -> List:
    data_list = []
    logger.info(f"Loading data from {file_path}")
    if file_path.endswith(".gz"):
        with gzip.open(file_path, "rt", encoding="utf-8") as f:
            lines = f.readlines()
            for line in lines:
                data_list.append(json.loads(line))
    else:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in lines:
                data_list.append(json.loads(line))
    logger.info(f"Loaded {len(data_list)} entries")
    return data_list


def buildTree(file_path: str) -> PKITree:
    tree = PKITree()
    data_list = load_rpki_archive(file_path)
    ctr = 0
    for data in data_list:
        if "type" not in data:
            continue
        if (data["type"] == "roa") or (data["type"] == "ca_cert"):
            ski = data["ski"]
            if "aki" not in data:
                aki = ""
            else:
                aki = data["aki"]
            tree.insert_node(ski, aki, data=data)
            ctr += 1
    tree.populate_resources()
    logger.info(f"Tree built with {ctr} nodes")
    return tree
