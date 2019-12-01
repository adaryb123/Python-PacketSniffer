def find_number_and_string(line):
    i = 0
    while (line[i] != " "):
        i += 1
    return line[:i] , line[i+1:]


def read_data_file(file_name,value,default = "not found"):
    with open("data_files/"+file_name+".txt") as data_file:
        line = data_file.readline()
        while (line != ""):
            number,description = find_number_and_string(line)
            data_length = len(str(value))
            if (number == str(value)) or (str(int(number,16)) == str(value)):
                  data_file.close()
                  return description[:-1]
            line = data_file.readline()
    
    data_file.close()
    return default