from time import time, sleep

from zkverifier.operations import payForValidMagicSquare
from zkverifier.util import getBalances
from zkverifier.testing.setup import getAlgodClient
from zkverifier.testing.resources import getTemporaryAccount


def verify_proof():
    client = getAlgodClient()

    print("Generating temporary accounts...")
    donor = getTemporaryAccount(client)
    claimer = getTemporaryAccount(client)

    print(f"donor account: {donor.getAddress()}\n");
    print(f"claimer account: {claimer.getAddress()}\n");

    print("donor balances:", getBalances(client, donor.getAddress()))
    print("claimer balances:", getBalances(client, claimer.getAddress()), "\n")

    payForValidMagicSquare(
        client = client,
        donor = donor,
        claimer = claimer
    )
    
    print("donor balances:", getBalances(client, donor.getAddress()))
    print("claimer balances:", getBalances(client, claimer.getAddress()), "\n")

verify_proof()
