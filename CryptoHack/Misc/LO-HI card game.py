from functools import total_ordering
from Crypto.Random import random
from pwn import * 
import json 

io = remote('socket.cryptohack.org', 13383)

VALUES = ['Ace', 'Two', 'Three', 'Four', 'Five', 'Six',
          'Seven', 'Eight', 'Nine', 'Ten', 'Jack', 'Queen', 'King']
SUITS = ['Clubs', 'Hearts', 'Diamonds', 'Spades']

@total_ordering
class Card:
    def __init__(self, value, suit):
        self.value = value
        self.suit = suit

    def __str__(self):
        return f"{self.value} of {self.suit}"

    def __eq__(self, other):
        return self.value == other.value

    def __gt__(self, other):
        return VALUES.index(self.value) > VALUES.index(other.value)

# Perform a smarter (probabilistic) pick, basically pick the option where
# there are more possiblities
def smart_pick(hand, deck):
    hand_idx = deck.index(hand)
    value = hand_idx % 13 

    if value - 0 > 12 - value: 
        return 'l'
    else:
        return 'h'

# Reconstruct the RNG state from the value of the card returned 
def reconstruct_rng_state(card_indexes):
    state = 0 
    indexes = card_indexes
    for index in indexes:
        state *= 52
        state += index 
    return state 

# Collect the value of cards
def collect_cards():
    deck = [Card(value, suit) for suit in SUITS for value in VALUES]
    deck = list(map(lambda x: str(x), deck)) # string representation of deck

    shuffle_states = []
    current_shuffle = []
    hand = None 
    for _ in range(34): # 34 because there is always 11 shuffles (in local testing)
        if hand:
            # If this is not the first pick, then do a smart pick
            pick = smart_pick(hand, deck)
        else: 
            # Otherwise just randomly pick
            pick = random.choice(['l', 'h'])
        
        # Result of the pick
        if _ == 0:
            result = json.loads(io.recvline().decode())
        else:
            io.sendline(json.dumps({'choice': pick}).encode())
            result = json.loads(io.recvline().decode())
        
        hand = result['hand']
        msg = result['msg']
        
        # If the deck is reshuffled, then append the current shuffle to the shuffle states
        if "reshuffle" in msg: 
            if 'Welcome' not in msg: 
                current_shuffle.append(deck.index(hand))
                shuffle_states.append(current_shuffle)
                current_shuffle = []
                continue
        
        current_shuffle.append(deck.index(hand))    
        
        # Only three shuffled decks are needed
        if len(shuffle_states) == 3:
            return shuffle_states

# Recover the mul, inc of the PRNG
def recover_mul_inc(shuffle_states):
    a, b, c = list(map(lambda x: reconstruct_rng_state(x), shuffle_states))
    mod = 2 ** 61 - 1
    temp1 = (c - b) % mod 
    temp2 = pow(b - a, -1, mod)

    recover_mul = (temp1 * temp2) % mod 
    recover_inc = (b - recover_mul * a) % mod 

    return (recover_mul, recover_inc, c)

# Generate the value of the RNG
def rng(mul, inc, state):
    mod = 2 ** 61 - 1
    return (mul * state + inc) % mod 

# Generate the shuffled deck
def rebase(n, b=52):
    if n < b:
        return [n]
    else:
        return [n % b] + rebase(n // b, b)

deck = [Card(value, suit) for suit in SUITS for value in VALUES]
deck = list(map(lambda x: str(x), deck)) # string representation of deck

# Recover the mul, inc from the 3 numbers retrieved from the cards
mul, inc, state = recover_mul_inc(collect_cards())
next_state = rng(mul, inc, state)
shuffled_deck = rebase(next_state)

current_card = shuffled_deck.pop()

for i in range(200 - 34):
    current_card_value = current_card % 13 
    next_card = shuffled_deck.pop()
    next_card_value = next_card % 13 

    print("Current card:", deck[current_card], end="")
    print(" Next card:", deck[next_card])
    if next_card_value < current_card_value:
        io.sendline(json.dumps({'choice': 'l'}).encode())
    else:
        io.sendline(json.dumps({'choice': 'h'}).encode())

    print(io.recvline().decode())
    current_card = next_card
    
    if len(shuffled_deck) == 0:
        state = next_state
        next_state = rng(mul, inc, next_state)
        shuffled_deck = rebase(next_state)

io.sendline(json.dumps({'choice': 'l'}).encode())
io.interactive()