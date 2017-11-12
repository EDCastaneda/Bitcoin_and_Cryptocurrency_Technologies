/*
Created by ECastaneda for the coursera program on crypto!
November 5th, 2017
*/
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;


public class TxHandler {

    public UTXOPool utxoPool;
    private Crypto crypto;
    
    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {        
        
        // Create the copy of the pool
        this.utxoPool = new UTXOPool(utxoPool);
        
        // create a Crypto object
        this.crypto = new Crypto();
                
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        
        int numInputsTX = tx.numInputs();
        int numOutputsTX = tx.numOutputs();
        double accInputValues = 0.0;                
        double accOutputValues = 0.0;                
        
        
        
        // Loop over all the inputs
        for(int input_index = 0; input_index < numInputsTX; input_index++) {            
            byte[] input_PrevTxHash = tx.getInput(input_index).prevTxHash;                
            byte[] input_sig = tx.getInput(input_index).signature;
            int input_index_in_tx = tx.getInput(input_index).outputIndex;
            UTXO utxo_temp = new UTXO(input_PrevTxHash,input_index_in_tx);                
            if(utxoPool.contains(utxo_temp)){
                // Valid reference to utxo in pool, (1)
                Transaction.Output tx_output = utxoPool.getTxOutput(utxo_temp); 
                accInputValues += tx_output.value;
                PublicKey output_pk = tx_output.address;                       
                // Verify that the signature in tx is valid, (2)       
                boolean isSignatureVerified = crypto.verifySignature(output_pk,
                        tx.getRawDataToSign(input_index),input_sig);
                if(!isSignatureVerified){
                    // The signature is not valid, invalid transaction
                    return false;
                }                
            }else{
                // the utxo is not in pool, invalid transaction
                return false;
            }
        } 
        
        // Verify that each input points to a unique utxo in pool, (3)        
        if(numInputsTX>1)
        {
            for(int input_index = 0; input_index < numInputsTX; input_index++) 
            {                 
                for(int input_index2 = input_index+1; input_index2 < numInputsTX; input_index2++) 
                { 
                    // Take the prevHash of the first index
                    byte[] input_PrevTxHash1 = tx.getInput(input_index).prevTxHash;
                    int input_index_1 = tx.getInput(input_index).outputIndex;
                    UTXO utxo_temp1 = new UTXO(input_PrevTxHash1,input_index_1);
                    
                    // Take the prevHash of the second index
                    byte[] input_PrevTxHash2 = tx.getInput(input_index2).prevTxHash;
                    int input_index_2 = tx.getInput(input_index2).outputIndex;
                    UTXO utxo_temp2 = new UTXO(input_PrevTxHash2,input_index_2);
                    
                    // Compare hash length and index
                    if(utxo_temp1.equals(utxo_temp2))
                    {
                        return false;
                    }
                                   
                }
            }           
        }
        
        // verify that the outputs' values are nonnegative, (4) 
        for(int output_index=0; output_index<numOutputsTX; output_index++){
            double output_value = tx.getOutput(output_index).value;
            if(output_value>=0){
                accOutputValues += output_value;
            }else{
                return false;
            }                
        }            
        
        // Verify that sum(output values)>=sum(input values), (5)
        if(accInputValues>=accOutputValues){
            return true;
        }else{
            return false;
        }
        
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */    
    public Transaction[] handleTxs(Transaction[] possibleTxs) {              
        
        int num_possTXs = possibleTxs.length;       
        int[] invalidIndices = new int[num_possTXs];
        int num_invalid_tx = 0;
                
        // Find the valid transactions
        for(int tx_ind=0; tx_ind<num_possTXs; tx_ind++){
            if(isValidTx(possibleTxs[tx_ind])){                       
                invalidIndices[tx_ind] = -1;                
                
                int num_outputs = possibleTxs[tx_ind].numOutputs();
                for(int output_ind=0; output_ind<num_outputs; output_ind++)
                {                      
                    UTXO utxo_temp = new UTXO(possibleTxs[tx_ind].getHash(),output_ind);
                    utxoPool.addUTXO(utxo_temp, possibleTxs[tx_ind].getOutput(output_ind));
                }
                                
                int num_inputs_in_tx = possibleTxs[tx_ind].numInputs();
                for(int input_ind=0; input_ind<num_inputs_in_tx; input_ind++)
                {
                    byte[] hashPointer = possibleTxs[tx_ind].getInput(input_ind).prevTxHash;                
                    int index_PrevTX = possibleTxs[tx_ind].getInput(input_ind).outputIndex;
                    UTXO utxo_temp = new UTXO(hashPointer,index_PrevTX);
                    utxoPool.removeUTXO(utxo_temp);
                }
                                                                
            }else{
                num_invalid_tx += 1;
                invalidIndices[tx_ind] = tx_ind;
            }
        }
        
        // Create an array of accepted transactions
        int num_valid_tx = num_possTXs - num_invalid_tx;        
        Transaction[] acceptedTXS = new Transaction[num_valid_tx];
        int valid_index = 0;
        
        for(int tx_ind=0; tx_ind<num_possTXs; tx_ind++){
            if( invalidIndices[tx_ind]==-1 ){                       
                acceptedTXS[valid_index] = new Transaction(possibleTxs[tx_ind]);
                valid_index+=1;
            }
        }
         
                
        return acceptedTXS;
    }
    
    

}
