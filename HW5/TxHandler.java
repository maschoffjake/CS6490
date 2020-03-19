import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class TxHandler {

	// Defensive copy of the current pool that is passed in, used to compare transactions against
	public UTXOPool currentUTXOPool;
	Set<UTXO> claimed;

	/* Creates a public ledger whose current UTXOPool (collection of unspent 
	 * transaction outputs) is utxoPool. This should make a defensive copy of 
	 * utxoPool by using the UTXOPool(UTXOPool uPool) constructor.
	 */
	public TxHandler(UTXOPool utxoPool) {
		// IMPLEMENT THIS
		currentUTXOPool = new UTXOPool(utxoPool);
	}

	/* Returns true if 
	 * (1) all outputs claimed by tx are in the current UTXO pool, 
	 * (2) the signatures on each input of tx are valid, 
	 * (3) no UTXO is claimed multiple times by tx, 
	 * (4) all of tx’s output values are non-negative, and
	 * (5) the sum of tx’s input values is greater than or equal to the sum of   
	        its output values;
	   and false otherwise.
	 */

	public boolean isValidTx(Transaction tx) {
		claimed = new HashSet<>();
		// Check (1), (2) and (3)
		for (int index = 0; index < tx.numInputs(); index++) {

			// Grab the current index
			Transaction.Input input = tx.getInput(index);

			// Check to see if this is a valid input (see if there is valid unspent UTXO associated with it)
			UTXO mappedOutput = new UTXO(input.prevTxHash, input.outputIndex);

			// Not a valid unspent transaction with this input!
			if (!currentUTXOPool.contains(mappedOutput)) {
				return false;
			}

			// (3) check to see if this UTXO has already been claimed by an input, if so invalid!
			if (claimed.contains(mappedOutput)) {
				return false;
			}
			claimed.add(mappedOutput);

			// Lastly, check to see if the signature is valid (2)
			Transaction.Output claimedOutput = currentUTXOPool.getTxOutput(mappedOutput);
			if (!claimedOutput.address.verifySignature(tx.getRawDataToSign(index), input.signature)) {
				return false;
			}
		}


		// Check (4)
		for (Transaction.Output output : tx.getOutputs()) {
			if (output.value < 0){
				return false;
			}
		}

		// Check (5)
		double outputSum = 0;
		double inputSum = 0;
		for (Transaction.Output output : tx.getOutputs()) {
			// Get the output values
			outputSum += output.value;
		}
		for (Transaction.Input input : tx.getInputs()) {
			// Get the output value associated with this input
			UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);

			// Add this to inputSum
			inputSum += currentUTXOPool.getTxOutput(utxo).value;
		}
		if (outputSum > inputSum)  {
			return false;
		}

		return true;
	}

	/* Handles each epoch by receiving an unordered array of proposed 
	 * transactions, checking each transaction for correctness, 
	 * returning a mutually valid array of accepted transactions, 
	 * and updating the current UTXO pool as appropriate.
	 */
	public Transaction[] handleTxs(Transaction[] possibleTxs) {
		ArrayList<Transaction> retList = new ArrayList<>();
		for (Transaction transaction : possibleTxs) {
			// Check to see if this transaction is valid
			if (isValidTx(transaction)) {
				retList.add(transaction);

				// If it is valid, we must also remove all spent transactions used in this transaction
				for (Transaction.Input input : transaction.getInputs()) {
					UTXO utxoUsed = new UTXO(input.prevTxHash, input.outputIndex);
					currentUTXOPool.removeUTXO(utxoUsed);
				}

				// Also add outputs to UTXO pool so future transactions can use
				byte [] currTxHash = transaction.getHash();
				for (int index = 0; index < transaction.numOutputs(); index++) {
					// Create new UTXO to add to pool
					UTXO utxoCreated = new UTXO(currTxHash, index);
					currentUTXOPool.addUTXO(utxoCreated, transaction.getOutput(index));
				}
			}
		}
		Transaction[] retArray = new Transaction[retList.size()];
		for (int i = 0; i < retList.size(); i++){
			retArray[i] = retList.get(i);
		}
		return retArray;
	}

} 
