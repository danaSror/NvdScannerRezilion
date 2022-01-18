import winreg
from winreg import QueryValueEx, EnumKey
import logging
import pandas as pd


class RegistryConnection:
    def __init__(self):
        self.registry_cursor = None
        self.dir_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        self.hkey_dict = {winreg.HKEY_LOCAL_MACHINE: 'HKEY_LOCAL_MACHINE',
                          winreg.HKEY_CURRENT_USER: 'HKEY_CURRENT_USER'}

    def connect_to_main_key(self, key):
        self.registry_cursor = winreg.ConnectRegistry(None, key)

    def open_element_by_key(self, mainKey, key):
        try:
            return winreg.OpenKey(mainKey, key)
        except EnvironmentError:
            logging.info("***cursor is empty ***")

    def get_software_data_by_field(self, software_key, requested_data_field):
        try:
            return QueryValueEx(software_key, requested_data_field)
        except FileNotFoundError:
            return ['']

    def get_software_enum_key(self, directory_conn, software_index) :
        return EnumKey(directory_conn, software_index)


class InstalledSoftware:
    def __init__(self):
        self.reg_conn = RegistryConnection()
        self.requested_data_field = "DisplayName"  # choose here which field you need
        self.log_configures()

    def get_installed_software(self):
        software_lst = []
        for hkey in self.reg_conn.hkey_dict:
            self.reg_conn.connect_to_main_key(hkey)  # establish connection to registry
            dir_conn = self.reg_conn.open_element_by_key(self.reg_conn.registry_cursor,
                                                         self.reg_conn.dir_path)  # establish connection to registry dir
            for i in range(1024):
                try:
                    software_key = self.reg_conn.get_software_enum_key(dir_conn, i)
                    software_conn = self.reg_conn.open_element_by_key(dir_conn,
                                                                      software_key)  # establish connection to software file
                    val = self.reg_conn.get_software_data_by_field(software_conn, self.requested_data_field)
                    software_lst.append(val[0])
                except FileNotFoundError:
                    continue
                except EnvironmentError:
                    logging.info(r"*** %s files was found in %s ***" % (i, self.reg_conn.hkey_dict[hkey]))
                    break
        return software_lst

    def log_configures(self):
        log_name = 'log_file.log'
        logging.basicConfig(filename=log_name,
                            filemode='a',
                            format='%(asctime)s %(message)s',
                            level=logging.INFO)

    def log_lists(self, lst):
        for k, elm in enumerate(lst):
            logging.info("{}: {}".format(k + 1, elm[0]))

    def remove_empty_list_items(self, lst):
        len_cols = len(lst[0])  # cleaning the list from empty items
        len_rows = len(lst)
        col = -1
        while col < len_cols - 1:
            col += 1
            for row in range(0, len_rows):
                if lst[row][col] == '':
                    delete = True
                else:
                    break
                if row == (len_rows - 1) and delete:
                    for newRow in range(0, len_rows):
                        del lst[newRow][col]
                    len_cols = len_cols - 1
                    col -= 1

    def dump_software_lst_to_json(self, requested_fields_lst):
        final_lst = []
        for field in requested_fields_lst:
            self.requested_data_field = field
            final_lst.append(self.get_installed_software())
        self.remove_empty_list_items(final_lst)

        df = pd.DataFrame(data=final_lst)
        df = df.rename(index={df.index[i]: requested_fields_lst[i] for i in range(len(requested_fields_lst))})
        df.to_json("registry_data.json")

