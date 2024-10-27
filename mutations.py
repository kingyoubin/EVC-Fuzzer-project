# mutations.py

import random
import string

# Mutation functions for each element
def mutate_ProtocolNamespace(value):
    # Ensure value is a string of length <= 100
    # Mutate the string but keep length <= 100
    mutation_funcs = [value_flip_string, random_value_string, random_deletion_string, random_insertion_string]
    mutated_value = random.choice(mutation_funcs)(value)
    if len(mutated_value) > 100:
        mutated_value = mutated_value[:100]
    return mutated_value

def mutate_VersionNumberMajor(value):
    # Mutate the unsigned integer
    value_int = safe_int(value, default=1)
    mutated_value_int = mutate_unsigned_int(value_int)
    return str(mutated_value_int)

def mutate_VersionNumberMinor(value):
    # Mutate the unsigned integer
    value_int = safe_int(value, default=1)
    mutated_value_int = mutate_unsigned_int(value_int)
    return str(mutated_value_int)

def mutate_SchemaID(value):
    # Mutate the unsigned byte (0-255)
    value_int = safe_int(value, default=0)
    mutated_value_int = mutate_unsigned_byte(value_int)
    return str(mutated_value_int)

def mutate_Priority(value):
    # Mutate the unsigned byte between 1 and 20
    value_int = safe_int(value, default=1)
    mutated_value_int = mutate_priority(value_int)
    return str(mutated_value_int)

# Helper functions for mutations
def safe_int(value, default=0):
    try:
        return int(value)
    except ValueError:
        return default

def mutate_unsigned_int(value):
    # Generate a random unsigned int (non-negative integer)
    # Apply small mutations to the value
    mutation = random.choice(['increment', 'decrement', 'random'])
    if mutation == 'increment':
        value += random.randint(1, 10)
    elif mutation == 'decrement':
        value = max(0, value - random.randint(1, 10))
    elif mutation == 'random':
        value = random.randint(0, value + 100)
    return value

def mutate_unsigned_byte(value):
    # Generate a random unsigned byte (0-255)
    mutation = random.choice(['increment', 'decrement', 'random'])
    if mutation == 'increment':
        value = min(255, value + random.randint(1, 10))
    elif mutation == 'decrement':
        value = max(0, value - random.randint(1, 10))
    elif mutation == 'random':
        value = random.randint(0, 255)
    return value

def mutate_priority(value):
    # Generate a random value between 1 and 20
    mutation = random.choice(['increment', 'decrement', 'random'])
    if mutation == 'increment':
        value = min(20, value + random.randint(1, 5))
    elif mutation == 'decrement':
        value = max(1, value - random.randint(1, 5))
    elif mutation == 'random':
        value = random.randint(1, 20)
    return value

# String mutation functions ensuring length constraints
def value_flip_string(value):
    if len(value) < 2:
        return value
    idx1, idx2 = random.sample(range(len(value)), 2)
    value_list = list(value)
    value_list[idx1], value_list[idx2] = value_list[idx2], value_list[idx1]
    return ''.join(value_list)

def random_value_string(value):
    if len(value) == 0:
        return value
    idx = random.randrange(len(value))
    new_char = random.choice(string.printable)
    value_list = list(value)
    value_list[idx] = new_char
    return ''.join(value_list)

def random_deletion_string(value):
    if len(value) == 0:
        return value
    idx = random.randrange(len(value))
    value_list = list(value)
    del value_list[idx]
    return ''.join(value_list)

def random_insertion_string(value):
    # Randomly select insertion position
    insert_idx = random.randrange(len(value) + 1)
    # Randomly select character to insert
    random_char = random.choice(string.printable)
    value_list = list(value)
    value_list.insert(insert_idx, random_char)
    return ''.join(value_list)
