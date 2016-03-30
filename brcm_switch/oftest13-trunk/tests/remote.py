"""
Platform configuration file
platform == remote
"""

remote_port_map = {
    3  : "eth2",
    6  : "eth3",
    11 : "eth4",
    20 : "eth5"
    }
def platform_config_update(config):
    """
    Update configuration for the remote platform

    @param config The configuration dictionary to use/update
    This routine defines the port map used for this configuration
    """

    global remote_port_map
    config["port_map"] = remote_port_map.copy()
    config["caps_table_idx"] = 0
