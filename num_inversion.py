f = open("order.txt", "r")
out_of_order = f.read().split(',')

num_inversions = 0
for i in range(len(out_of_order)):
    for j in range(i + 1, len(out_of_order)):
        if out_of_order[j] < out_of_order[i]:
            num_inversions += 1

print(num_inversions)

f.close()