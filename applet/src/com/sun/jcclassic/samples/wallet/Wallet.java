/** 
 * Copyright (c) 1998, 2017, Oracle and/or its affiliates. All rights reserved.
 * 
 */

/*
 */

/*
 * @(#)Wallet.java	1.11 06/01/03
 */

package com.sun.jcclassic.samples.wallet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

public class Wallet extends Applet {
	
    final static byte WALLET_CLA = (byte) 0x80;
    
    final static short MAX_MONEY_AMOUNT          = 0x2710;
    final static short MAX_LOYALTY_POINTS_AMOUNT = 0x12C;
    final static short MAX_TRANSACTION_AMOUNT    = 0x3E8;

    /* INS byes in the command APDU header */
    
    final static byte VERIFY      = (byte) 0x20;
    final static byte CREDIT      = (byte) 0x30;
    final static byte DEBIT       = (byte) 0x40;
    final static byte GET_BALANCE = (byte) 0x50;
    final static byte CHANGE_PIN  = (byte) 0x70;

    final static byte PIN_TRY_LIMIT = (byte) 0x03;
    final static byte MAX_PIN_SIZE  = (byte) 0x08;
    
    final static byte MONEY_PARAMETER         = (byte) 0x01;
    final static byte LOYALTY_PARAMETER       = (byte) 0x02;
    final static byte MONEY_LOYALTY_PARAMETER = (byte) 0x03;
    
    /* Response APDU values */

    final static short SW_VERIFICATION_FAILED             = 0x6300;
    final static short SW_PIN_VERIFICATION_REQUIRED       = 0x6301;
    final static short SW_INVALID_TRANSACTION_AMOUNT      = 0x6A83;
    final static short SW_EXCEED_MAXIMUM_BALANCE          = 0x6A84;
    final static short SW_NEGATIVE_BALANCE                = 0x6A85;
    final static short SW_NEGATIVE_MONEY_BALANCE          = 0x6A86;
    final static short SW_NEGATIVE_LOYALTY_POINTS_BALANCE = 0x6A87;
    final static short SW_SECURITY_STATUS_NOT_SATISFIED   = 0x6A86;

    static OwnerPIN pin;
    static short balanceMoney;
    static short balanceLoyalty;

    private Wallet(byte[] bArray, short bOffset, byte bLength) {

        // It is good programming practice to allocate
        // all the memory that an applet needs during
        // its lifetime inside the constructor
        pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);

        byte iLen = bArray[bOffset]; // aid length
        bOffset = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // applet data length

        // The installation parameters contain the PIN
        // initialization value
        pin.update(bArray, (short) (bOffset + 1), aLen);
        register();

    } // end of the constructor

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // create a Wallet applet instance
        new Wallet(bArray, bOffset, bLength);
    } // end of install method

    @Override
    public boolean select() {
        // The applet declines to be selected
        // if the pin is blocked.
        if (pin.getTriesRemaining() == 0) {
            return false;
        }

        return true;
    }

    @Override
    public void deselect() {
        // reset the pin value
        pin.reset();
    }

    @Override
    public void process(APDU apdu) {

        // APDU object carries a byte array (buffer) to
        // transfer incoming and outgoing APDU header
        // and data bytes between card and CAD

        // At this point, only the first header bytes
        // [CLA, INS, P1, P2, P3] are available in
        // the APDU buffer.
        // The interface javacard.framework.ISO7816
        // declares constants to denote the offset of
        // these bytes in the APDU buffer

        byte[] buffer = apdu.getBuffer();
        // check SELECT APDU command

        if (apdu.isISOInterindustryCLA()) {
        	//A4 represents the select
            if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
                return;
            }
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // verify the reset of commands have the
        // correct CLA byte, which specifies the
        // command structure
        if (buffer[ISO7816.OFFSET_CLA] != WALLET_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case GET_BALANCE:
                getBalance(apdu);
                return;
            case DEBIT:
                debit(apdu);
                return;
            case CREDIT:
                credit(apdu);
                return;
            case VERIFY:
                verify(apdu);
                return;
            case CHANGE_PIN:
            	changePIN(apdu);
            	return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

    } // end of process method
    
    private void credit(APDU apdu) {

        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer = apdu.getBuffer();

        // Lc byte denotes the number of bytes in the
        // data field of the command APDU
        byte numBytes = buffer[ISO7816.OFFSET_LC];

        // indicate that this APDU has incoming data
        // and receive data starting from the offset
        // ISO7816.OFFSET_CDATA following the 5 header
        // bytes.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // it is an error if the number of data bytes
        // read does not match the number in Lc byte
        if ((numBytes != 2) || (byteRead != 2)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        // get the credit amount
        
        byte creditAmountByte1 = buffer[ISO7816.OFFSET_CDATA];
        byte creditAmountByte2 = buffer[ISO7816.OFFSET_CDATA + 1];
        
        short creditAmount = (short)( (creditAmountByte1 << 8) | creditAmountByte2 & 0xFF);
        
        // check the credit amount
        if ((creditAmount > MAX_TRANSACTION_AMOUNT) || (creditAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }
        
        // check the new balance
        if ((short) (balanceMoney + creditAmount) > MAX_MONEY_AMOUNT) {
            ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
        }

        // credit the amount
        balanceMoney = (short) (balanceMoney + creditAmount);
    } // end of deposit method
    
    private void debitMoney(APDU apdu) {
    	
    	byte[] buffer = apdu.getBuffer();
    	
        byte numBytes  = buffer[ISO7816.OFFSET_LC];
        byte bytesRead  = (byte) (apdu.setIncomingAndReceive());
        
        if ((numBytes != 2) || (bytesRead != 2)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short debitAmount = (short)(buffer[ISO7816.OFFSET_CDATA] << 8 | buffer[ISO7816.OFFSET_CDATA + 1] & 0xFF);

        // check debit amount
        if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }
        
        // check the new balance
        if ((short) (balanceMoney - debitAmount) < (short) 0) {
            ISOException.throwIt(SW_NEGATIVE_MONEY_BALANCE);
        }

        balanceMoney = (short) (balanceMoney - debitAmount);
        
        short newLoyaltyPoints = (short) (balanceLoyalty + ( debitAmount / 10 ));
        
        if(newLoyaltyPoints <= MAX_LOYALTY_POINTS_AMOUNT) {
        	balanceLoyalty = newLoyaltyPoints;
        }
    }
    
    private void debitLoyaltyPoints(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	
        byte numBytes  = buffer[ISO7816.OFFSET_LC];
        byte bytesRead  = (byte) (apdu.setIncomingAndReceive());
        
        if ((numBytes != 2) || (bytesRead != 2)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short debitAmount = (short)(buffer[ISO7816.OFFSET_CDATA] << 8 | buffer[ISO7816.OFFSET_CDATA + 1] & 0xFF);
        
        if ((debitAmount > MAX_TRANSACTION_AMOUNT) || (debitAmount < 0)) {
            ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }
        
        if ((short) (balanceLoyalty - debitAmount) < (short) 0) {
            ISOException.throwIt(SW_NEGATIVE_LOYALTY_POINTS_BALANCE);
        }
        
        balanceLoyalty = (short) (balanceLoyalty - debitAmount);
    }
    
    private void debitMoneyLoyaltyPoints(APDU apdu) {
    	byte[] buffer = apdu.getBuffer();
    	
    	byte numBytes  = buffer[ISO7816.OFFSET_LC];
        byte bytesRead  = (byte) (apdu.setIncomingAndReceive());
        
        if ((numBytes != 4) || (bytesRead != 4)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        short moneyDebitAmount         = (short)(buffer[ISO7816.OFFSET_CDATA]     << 8 | buffer[ISO7816.OFFSET_CDATA + 1] & 0xFF);
        short loyaltyPointsDebitAmount = (short)(buffer[ISO7816.OFFSET_CDATA + 2] << 8 | buffer[ISO7816.OFFSET_CDATA + 3] & 0xFF);
        
        if((moneyDebitAmount > MAX_TRANSACTION_AMOUNT) || (moneyDebitAmount < 0)) {
        	ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }
        
        if((loyaltyPointsDebitAmount > MAX_TRANSACTION_AMOUNT) || (loyaltyPointsDebitAmount < 0)) {
        	ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
        }

        short leftoverSumMoney   = (short) (balanceMoney - moneyDebitAmount);
        short leftoverSumLoyalty = (short) (balanceLoyalty - loyaltyPointsDebitAmount);
        
        if (leftoverSumMoney >= 0 && leftoverSumLoyalty >= 0) {
        	balanceMoney   = leftoverSumMoney;
        	balanceLoyalty = (short)(leftoverSumLoyalty + (short)(moneyDebitAmount / 10));
        } else if(leftoverSumMoney < 0 && leftoverSumLoyalty < 0){
        	 ISOException.throwIt(SW_NEGATIVE_BALANCE);
        } else if(leftoverSumMoney < 0) {
        	ISOException.throwIt(SW_NEGATIVE_MONEY_BALANCE);
        } else if(leftoverSumLoyalty < 0) {
        	ISOException.throwIt(SW_NEGATIVE_LOYALTY_POINTS_BALANCE);
        }
    }
    
    private void debit(APDU apdu) {

        // access authentication
        if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }

        byte[] buffer  = apdu.getBuffer();

        switch(buffer[ISO7816.OFFSET_P1]){
        	case MONEY_PARAMETER:
        		debitMoney(apdu);
        		break;
        case LOYALTY_PARAMETER:
        		debitLoyaltyPoints(apdu);
        		break;
        case MONEY_LOYALTY_PARAMETER:
        		debitMoneyLoyaltyPoints(apdu);
        		break;
    	default:
    		ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
    }
  
    private void getBalance(APDU apdu) {
    	
    	if(!pin.isValidated()) {
    		ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
    	}
    	
        byte[] buffer = apdu.getBuffer();
        
        short length = 0;
        byte data[]  = new byte[10];
        
        switch(buffer[ISO7816.OFFSET_P1]) {
        	
	        case MONEY_PARAMETER:
	        	length  = 2;
	        	data[0] = (byte) (balanceMoney >> 8);
	        	data[1] = (byte) (balanceMoney & 0xFF);
	        	break;
	    	
	        case LOYALTY_PARAMETER:
	        	length  = 2;
	        	data[0] = (byte) (balanceLoyalty >> 8);
	        	data[1] = (byte) (balanceLoyalty & 0xFF);
	        	break;
	        	
	        case MONEY_LOYALTY_PARAMETER:
	        	length  = 4;
	        	data[0] = (byte) (balanceMoney >> 8);
	        	data[1] = (byte) (balanceMoney & 0xFF);
	        	data[2] = (byte) (balanceLoyalty >> 8);
	        	data[3] = (byte) (balanceLoyalty & 0xFF);
	        	break;
	        default:
	        	ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        
        short le = apdu.setOutgoing();
        
        if (le < length) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        apdu.setOutgoingLength((byte) length);

        for(short index = 0; index < length; index++){
        	buffer[index] = data[index];
        }

        apdu.sendBytes((short) 0, (short) length);
    } 
    
    private void changePIN(APDU apdu){
    	
    	byte[] buffer = apdu.getBuffer();
    	
    	short le = apdu.setOutgoing();
    	
    	if( le < 2 ){
    		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    	}
    	
    	apdu.setOutgoingLength((byte) 2);
    	
    	byte numBytes = buffer[ISO7816.OFFSET_LC];
    	
    	byte lenFirstPin = buffer[ISO7816.OFFSET_LC + 1];
    	
    	short startOfPinPosition = ISO7816.OFFSET_CDATA + 1;
    	
    	if (pin.getTriesRemaining() == 0) {
    		ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    	
    	if(pin.check(buffer, startOfPinPosition, lenFirstPin) == false){
    		ISOException.throwIt(SW_VERIFICATION_FAILED);
    	}
    	
    	byte lenSecondPin = buffer[(short)(ISO7816.OFFSET_LC + lenFirstPin + 2)];
    	
    	short startOfSecondPinPosition = (short)(ISO7816.OFFSET_LC + lenFirstPin + 3);
    	
    	pin.update(buffer, startOfSecondPinPosition, lenSecondPin);
//        register();
    }

    private void verify(APDU apdu) {

        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // check pin
        // the PIN data is read into the APDU buffer
        // at the offset ISO7816.OFFSET_CDATA
        // the PIN data length = byteRead
        if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {
            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }

    } // end of validate method
} // end of class Wallet

