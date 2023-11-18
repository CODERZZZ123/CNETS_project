import csv

def convert_format(input_file, output_file):
    with open(input_file, 'r') as csvfile:
        reader = csv.reader(csvfile, delimiter='\t')
        next(reader)  # Skip the header

        # Prepare output data
        output_data = [["protocol", "port", "description"]]
        dict = {}
        for row_elem in reader:
            if(len(row_elem) < 1):
                continue
            row = row_elem[0]
            row_list = row.split(',')
            if len(row_list) < 4 :
                continue
            print(row_list)
            protocol = row_list[2].lower()  # Assuming the protocol is in lowercase
            if(protocol == ''):
                continue
            port_split = row_list[1].split('-')
            description = row_list[3]
            if description == '':
                continue
            port = None
            if len(port_split)  ==  2 :
                port_1 = None
                port_2 = None
                try:
                    port_1 =  int(port_split[0])
                except ValueError:
                    continue
                try:
                    port_2 =  int(port_split[1])
                except ValueError:
                    continue
                for i in range(port_1,port_2+1):
                    output_data.append([protocol.upper(), i, description])
                continue
            try :
                port = int(port_split[0])
            except ValueError:
                continue
            dict[(protocol.upper(),port)] = description
        
        csv_file = output_file

        with open(csv_file, 'w', newline='') as file:
            writer = csv.writer(file)
            

            writer.writerow(["protocol", "port", "description"])
            

            for (protocol, port), description in dict.items():
                writer.writerow([protocol, port, description])


# Example usage
convert_format("service_Data.csv", "all_2.csv")
