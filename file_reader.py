
def read_data_file(file_name,value,default = "not found"):
    with open("data_files/"+file_name+".txt") as data_file:
        line = data_file.readline()
        data_length = len(str(value))
        while line != "":
          if line[:data_length] == str(value):
              data_file.close()
              return line[data_length+1:-1]
          line = data_file.readline()
    
    data_file.close()
    return default