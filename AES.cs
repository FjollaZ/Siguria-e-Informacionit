using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DetyraAES
{
    public class AES  // Advanced Encryption Standard-AES
    {
        //Krijojme nje grupim  te konstanteve per madhesite e mundshme te celesit. Per 128, 193 dhe 256 bits.
        public enum KeySize { Bits128, Bits192, Bits256 };  

        //Nb paraqet madhesine e bllokut. Ne AES eshte 4 madhesia e bllokut(matrica e rendit 4X4) - 128 bits
        private int Nb;        
        //Nk paraqet madhesine e celesit. 4, 6, 8 jane vlerat e mundshme. (128, 192 dhe 256 bits)
        private int Nk;         
       // Numri i cikleve (number of rounds).
       //10 cikle -> per celes 128 bitsh
       //12 cikle -> per celes 192 bitsh
       //14 cikle -> per celes 256 bitsh
        private int Nr;        

        //krijojme nje byte array per celes berthame. Madhesia do te jete 4 * madhesia e celesit
        private byte[] key;     
        //krijojme vargun dydimensional per Sbox(substitution box), bllokun e zevendesimit
        private byte[,] Sbox;   
        //krijojme vargun dydimensional per SBox-in invers
        private byte[,] iSbox;  
        //krijojme vargun dydimensional per key schedule
        private byte[,] w;     
        //krijojme vargun dydimensional per konstantet e roundeve (cikleve)  
        private byte[,] Rcon;   
        //krijojem vargu dydimensional qe paraqet matricen e gjendjes
        private byte[,] State; 


        //Konstruktori i klases AES  per inicializim te vlerave
        public AES(KeySize keySize, byte[] keyBytes)
        {
            //thirret funksioni setNBNkNr me parameter varesisht aq sa eshte madhesia e celesit 128,192 apo 256 bits.
            SetNbNkNr(keySize);

            //casemi tek array i key, qe paraqet celesin berthame dhe per cfaredo key size (Nk) behet *4 (4*4), (4*6), (4*8)
            this.key = new byte[this.Nk * 4];  // 16, 24, 32 bytes
            //Kopjon vlerat keybytes ne array-njedimensionale te quatur key, e vendos prej indeksit 0
            keyBytes.CopyTo(this.key, 0);

            //thirret funksioni BuildSbox()
            BuildSbox();
            //thirret funskioni invers i SBox-it
            BuildInvSbox();
            //thirret funksioni BuildRcon() per te krijuar konstantet e cikeleve te perseritjes
            BuildRcon();
            //thirret funksioni KeyExpansion per zgjerim te celsit ne nje key schedule
            KeyExpansion();  

        }  
       //Funksioni cipher per enkriptim, merr si parametra inputin dhe outputin
        
        public void Cipher(byte[] input, byte[] output)  
        {
            //matrica e gjendjes cdo here do te kete rendin 4X4, sepse  Nb=4 
            this.State = new byte[4, Nb];  
            for (int i = 0; i < (4 * Nb); ++i)
            {
                this.State[i % 4, i / 4] = input[i];
            }
           //Per pjesen e pare te celesit K1 aplikohet vetem funksioni AddRoundKey
            AddRoundKey(0);
            //Loop-a kryesore e round-it
            
            for (int round = 1; round <= (Nr - 1); ++round)  
            {
                //Keto funksione aplikohen per celesat K2 ....Kn-1
                SubBytes();
                ShiftRows();
                MixColumns();
                AddRoundKey(round);
            }  
            //Keto funksione thirren per celesine e fundit Kn
            SubBytes();
            ShiftRows();
            AddRoundKey(Nr);

            for (int i = 0; i < (4 * Nb); ++i)
            {
                output[i] = this.State[i % 4, i / 4];
            }

        }  // Cipher()
        
       //Funksioni InvCipher per dekriptim, merr si parametra inputin dhe outputin
   
        public void InvCipher(byte[] input, byte[] output)  
        {
            //matrica e gjendjes cdo here do t kete rendin 4X4, Nb=4
            this.State = new byte[4, Nb];  // always [4,4]
            for (int i = 0; i < (4 * Nb); ++i)
            {
                this.State[i % 4, i / 4] = input[i];
            }
        //Per pjesen e pare te celesit K1 aplikohet vetem funksioni AddRoundKey, por ne kete rast merr si parameter numrin e rounds
            AddRoundKey(Nr);
           //Loop-a kryesore e round-it per InvCipher
            for (int round = Nr - 1; round >= 1; --round)  
            {  
                //Keto funksione aplikohen per celesat K2 ....Kn-1
                InvShiftRows();
                InvSubBytes();
                AddRoundKey(round);
                InvMixColumns();
            }  
           //Keto funksione thirren per celesine e fundit Kn
            InvShiftRows();
            InvSubBytes();
            AddRoundKey(0);

            for (int i = 0; i < (4 * Nb); ++i)
            {
                output[i] = this.State[i % 4, i / 4];
            }

        }  

        //funksioni per vendosjen e vlerave te blok size-it, key size-it dhe numrit te roundeve varesisht prej madhesise se celesit(128, 192 apo 256)
        private void SetNbNkNr(KeySize keySize)
        {
            //Block size eshte gjithmone 4. 16 bytes = 128 bits per AES
            this.Nb = 4;     

            //vendosim kushtet varesisht nga madhesia e celesit (ne bits - KeySize) vendoset nje vlere per key size Nk dhe per numrin e cikleve te perseritjes Nr
            if (keySize == KeySize.Bits128)
            {
                //nese madhesia e celesit eshte 128 bits atehere key size Nk = 4, sepse  16 bytes = 128 bits, nderkaq numri i cikleve 10
                this.Nk = 4;   
                this.Nr = 10;  // rounds for algorithm = 10
            }
            //nese madhesia e celesit eshte 192 bits atehere key size Nk = 6, sepse 6 *4 = 24 bytes *8= 128 bits, nderkaq numri i cikleve 12
            else if (keySize == KeySize.Bits192)
            {
                this.Nk = 6;  
                this.Nr = 12;
            }
            //nese madhesia e celesit eshte 256 bits atehere key size Nk = 8, sepse 8*4 = 32 bytes = 256 bits, nderkaq numri i cikleve 14
            else if (keySize == KeySize.Bits256)
            {
                this.Nk = 8;   
                this.Nr = 14;
            }
        }  // SetNbNkNr()

        //krijohet funksioni BuildSbox
        private void BuildSbox()
        {
            //casemi ne vargun dydimensional te deklaruar Sbox dhe ja caktojme rendin 16X16, per te mbushur me te dhena heksadecimale
            this.Sbox = new byte[16, 16] {  
    /* 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
    /*0*/  {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    /*1*/  {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    /*2*/  {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    /*3*/  {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    /*4*/  {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    /*5*/  {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    /*6*/  {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    /*7*/  {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    /*8*/  {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    /*9*/  {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    /*a*/  {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    /*b*/  {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    /*c*/  {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    /*d*/  {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    /*e*/  {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    /*f*/  {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };

        }  

        private void BuildInvSbox()
        {
            //casemi ne vargun dydimensional te deklaruar si iSbox (inverse Substitution Box) dhe ja caktojme rendin 16X16, per te mbushur me te dhena heksadecimale
            this.iSbox = new byte[16, 16] {  
    /* 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
    /*0*/  {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    /*1*/  {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    /*2*/  {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    /*3*/  {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    /*4*/  {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    /*5*/  {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    /*6*/  {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    /*7*/  {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    /*8*/  {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    /*9*/  {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    /*a*/  {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    /*b*/  {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    /*c*/  {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    /*d*/  {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    /*e*/  {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    /*f*/  {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d} };

        }  
    //Funksioni per krijimin e konstanteve per rounds
        private void BuildRcon()
        {
            //casemi ne vargun dydimensional Rcon per konstantet e round-eve dhe krijojme nje byte array te rendit 11 rreshta 4 kolona
            //pasi qe per 128 bits Nk(key size)=4 dhe Nr(number of rounds)=10 krijojme rendin 11(0-10)rreshta dhe 4 kolona 
            //Vlerat ne kolonen e pare mbushen me vlere heksadecimale qe me konvertimne decimal i bie vlere e dyfishuar e vleres paraprake deri ne 128(per 128 bits).
            //1(0X01), 2(0X02), 4(0X04), 8(0X08), 16(0X10), 32(0X20), 64(0X40), 128(0X80), e me pas fillon vlera nga 27(0X1b), 54(0X36).
            this.Rcon = new byte[11, 4] { {0x00, 0x00, 0x00, 0x00},
                                   {0x01, 0x00, 0x00, 0x00},
                                   {0x02, 0x00, 0x00, 0x00},
                                   {0x04, 0x00, 0x00, 0x00},
                                   {0x08, 0x00, 0x00, 0x00},
                                   {0x10, 0x00, 0x00, 0x00},
                                   {0x20, 0x00, 0x00, 0x00},
                                   {0x40, 0x00, 0x00, 0x00},
                                   {0x80, 0x00, 0x00, 0x00},
                                   {0x1b, 0x00, 0x00, 0x00},
                                   {0x36, 0x00, 0x00, 0x00} };
        }  
      //Funksioni AddRound key - perzien nje vlere nga matrica e celesite me nje vlere nga matrica e mesazhit(plaintext) me funksionin xor. 
        // r -rreshti, c - kolona
        //funskioni xor zbatohet ne mes te mesazhit dhe celesit per te krijuar cyphertext
        private void AddRoundKey(int round)
        {

            for (int r = 0; r < 4; ++r)
            {
                for (int c = 0; c < 4; ++c)
                {
                    this.State[r, c] = (byte)((int)this.State[r, c] ^ (int)w[(round * 4) + c, r]);
                }
            }
        }  // AddRoundKey()

        //Funksioni SubBytes - gjene zevendesimin per mesazh nga Substitution Box (SBox) me kombinime dhe hapa specifik. 
        //AES merr rreshtin r dhe kolonen c nga mesazhi dhe zbaton funksionin e zevendesimit per secilin rresht dhe kolone te matrices se mesazhit, e keshtu krijohet matrica e cypher-it
        private void SubBytes()
        {
            for (int r = 0; r < 4; ++r)
            {
                for (int c = 0; c < 4; ++c)
                {
                    this.State[r, c] = this.Sbox[(this.State[r, c] >> 4), (this.State[r, c] & 0x0f)];
                }
            }
        }  // SubBytes

        private void InvSubBytes()
        {
            for (int r = 0; r < 4; ++r)
            {
                for (int c = 0; c < 4; ++c)
                {
                    this.State[r, c] = this.iSbox[(this.State[r, c] >> 4), (this.State[r, c] & 0x0f)];
                }
            }
        }  // InvSubBytes
        //Funksioni Shift Rows - merr matricen e mesazhit dhe nuk e ndryshon rreshtin e pare te kesaj matrice. Per rreshtine e dyte zhvendos nje kuti 
        //zhvendoset p.sh nga pozita 10  ne 13. Ne rreshtin e trete zhvendosen  per dy dhe ne rreshtin e katert per tri. 
        private void ShiftRows()
        {
            byte[,] temp = new byte[4, 4];
            //kopjon state-in (mesazhin) ne temp
            for (int r = 0; r < 4; ++r) 
            {
                for (int c = 0; c < 4; ++c)
                {
                    temp[r, c] = this.State[r, c];
                }
            }
           //shift temp ne state, fillon prej rreeshtit te dyte (r=1)
            for (int r = 1; r < 4; ++r)  
            {
                for (int c = 0; c < 4; ++c)
                {
                    this.State[r, c] = temp[r, (c + r) % Nb];
                }
            }
        }  

        private void InvShiftRows()
        {
            byte[,] temp = new byte[4, 4];
            for (int r = 0; r < 4; ++r)  
            {
                for (int c = 0; c < 4; ++c)
                {
                    temp[r, c] = this.State[r, c];
                }
            }
            for (int r = 1; r < 4; ++r)  
            {
                for (int c = 0; c < 4; ++c)
                {
                    this.State[r, (c + r) % Nb] = temp[r, c];
                }
            }
        }  
        
        //Funksioni Mix Columns - Ne kete funksion eshte nje matrice fikse e cila do te ndikoje ne matricen e mesazhit(state). 
        //Rreshti i pare - nuk ndryshon
        //Rreshti i dyte - Shift to left
        //Rreshti i trete - Shift to left + XOR
        private void MixColumns()
        {
            //kopjohet state ne temp
            byte[,] temp = new byte[4, 4];
            for (int r = 0; r < 4; ++r)  
            {
                for (int c = 0; c < 4; ++c)
                {
                    temp[r, c] = this.State[r, c];
                }
            }
           //Kater vlerat e nje kolone behen modulo multiplied ne Rijndael's Galois Field nga nje matrice e dhene .
            /*
              0e  0b 0d  09
              09  0e  0b  0d
              0c  09  0e  0b
              0b  0d  09  0e
            */
            for (int c = 0; c < 4; ++c)
            {
                this.State[0, c] = (byte)((int)gfmultby02(temp[0, c]) ^ (int)gfmultby03(temp[1, c]) ^
                                           (int)gfmultby01(temp[2, c]) ^ (int)gfmultby01(temp[3, c]));
                this.State[1, c] = (byte)((int)gfmultby01(temp[0, c]) ^ (int)gfmultby02(temp[1, c]) ^
                                           (int)gfmultby03(temp[2, c]) ^ (int)gfmultby01(temp[3, c]));
                this.State[2, c] = (byte)((int)gfmultby01(temp[0, c]) ^ (int)gfmultby01(temp[1, c]) ^
                                           (int)gfmultby02(temp[2, c]) ^ (int)gfmultby03(temp[3, c]));
                this.State[3, c] = (byte)((int)gfmultby03(temp[0, c]) ^ (int)gfmultby01(temp[1, c]) ^
                                           (int)gfmultby01(temp[2, c]) ^ (int)gfmultby02(temp[3, c]));
            }
        }  
       //Funksioni invers per MixColumns
        private void InvMixColumns()
        {
            byte[,] temp = new byte[4, 4];
            //kopjon state-in ne temp
            for (int r = 0; r < 4; ++r)  
            {
                for (int c = 0; c < 4; ++c)
                {
                    temp[r, c] = this.State[r, c];
                }
            }
            //Funksionet per gjenerimin e vlerave me kombinimet xor Galois Field
            for (int c = 0; c < 4; ++c)
            {
                this.State[0, c] = (byte)((int)gfmultby0e(temp[0, c]) ^ (int)gfmultby0b(temp[1, c]) ^
                                           (int)gfmultby0d(temp[2, c]) ^ (int)gfmultby09(temp[3, c]));
                this.State[1, c] = (byte)((int)gfmultby09(temp[0, c]) ^ (int)gfmultby0e(temp[1, c]) ^
                                           (int)gfmultby0b(temp[2, c]) ^ (int)gfmultby0d(temp[3, c]));
                this.State[2, c] = (byte)((int)gfmultby0d(temp[0, c]) ^ (int)gfmultby09(temp[1, c]) ^
                                           (int)gfmultby0e(temp[2, c]) ^ (int)gfmultby0b(temp[3, c]));
                this.State[3, c] = (byte)((int)gfmultby0b(temp[0, c]) ^ (int)gfmultby0d(temp[1, c]) ^
                                           (int)gfmultby09(temp[2, c]) ^ (int)gfmultby0e(temp[3, c]));
            }
        }  // InvMixColumns

        
         
        private static byte gfmultby01(byte b)
        {
            return b;
        }

        private static byte gfmultby02(byte b)
        {
            if (b < 0x80)
                return (byte)(int)(b << 1);
            else
                return (byte)((int)(b << 1) ^ (int)(0x1b));
        }

        private static byte gfmultby03(byte b)
        {
            return (byte)((int)gfmultby02(b) ^ (int)b);
        }

        private static byte gfmultby09(byte b)
        {
            return (byte)((int)gfmultby02(gfmultby02(gfmultby02(b))) ^
                           (int)b);
        }

        private static byte gfmultby0b(byte b)
        {
            return (byte)((int)gfmultby02(gfmultby02(gfmultby02(b))) ^
                           (int)gfmultby02(b) ^
                           (int)b);
        }

        private static byte gfmultby0d(byte b)
        {
            return (byte)((int)gfmultby02(gfmultby02(gfmultby02(b))) ^
                           (int)gfmultby02(gfmultby02(b)) ^
                           (int)(b));
        }

        private static byte gfmultby0e(byte b)
        {
            return (byte)((int)gfmultby02(gfmultby02(gfmultby02(b))) ^
                           (int)gfmultby02(gfmultby02(b)) ^
                           (int)gfmultby02(b));
        }
      //Funksioni per zgjerimin e celesit baze ne key schedule 
        private void KeyExpansion()
        {
            //casemi ne vargun dydimensional w qe e kemi deklaruar per key schedule, krijohet nje byte array me rendin ne vartesi nga block size (Nb) dhe number of rounds(Nr)
            //Nb eshte gjithmone 4 per cfaredo madhesie celesi, Nr mund te kete vlerat (10, 12 ose 14) varesisht celesit 128, 192 ose 256 bits. Nderkaq rendi i kolonave eshte 4
            //duke u perputhur me numrinne bajtave te nje fjale
            this.w = new byte[Nb * (Nr + 1), 4];  // 4 columns of bytes corresponds to a word
             
            //me nje for loop variabla row merr vlerat 0-3
            for (int row = 0; row < Nk; ++row)
            {
                //vargut per key schedule i jepet vlere duke u casur ne vargun e celesit baze "key". Madhesia do te jete 4 * key size
                this.w[row, 0] = this.key[4 * row];
                this.w[row, 1] = this.key[4 * row + 1];
                this.w[row, 2] = this.key[4 * row + 2];
                this.w[row, 3] = this.key[4 * row + 3];
            }
            //krijohet nje byte array me vlera te perkohshme e rendit 4
            byte[] temp = new byte[4];
            //vlera e row do te jete 4, 6 ose 8 dhe vendoset ne nje for loop deri sa arrihet vlera 4*(Nr+1)
            for (int row = Nk; row < Nb * (Nr + 1); ++row)
            {
                //mbushet me te dhena temp array duke u bazuar ne array-n e key schedule
                temp[0] = this.w[row - 1, 0]; temp[1] = this.w[row - 1, 1];
                temp[2] = this.w[row - 1, 2]; temp[3] = this.w[row - 1, 3];
                
                if (row % Nk == 0)
                {
                    //vlera nga temp behet rotate dhe zevendesohet me funksionet e krijuara 
                    temp = SubWord(RotWord(temp));
                    //numri i celesit te krijuar krijon cikle te ndryshme
                    temp[0] = (byte)((int)temp[0] ^ (int)this.Rcon[row / Nk, 0]);
                    temp[1] = (byte)((int)temp[1] ^ (int)this.Rcon[row / Nk, 1]);
                    temp[2] = (byte)((int)temp[2] ^ (int)this.Rcon[row / Nk, 2]);
                    temp[3] = (byte)((int)temp[3] ^ (int)this.Rcon[row / Nk, 3]);
                }
                //nese number of key eshte me i madhe se 6 dmth 8, ne temp aplikohet vetem funksioni per zevendesim
                else if (Nk > 6 && (row % Nk == 4))
                {
                    temp = SubWord(temp);
                }
                // rreshtit specifik nga key schedule per secilen kolone i jepet vlera e krijuar me xor te rreshtit ne key schedule bashke me vleren e rreshtit specifik ne temp
                this.w[row, 0] = (byte)((int)this.w[row - Nk, 0] ^ (int)temp[0]);
                this.w[row, 1] = (byte)((int)this.w[row - Nk, 1] ^ (int)temp[1]);
                this.w[row, 2] = (byte)((int)this.w[row - Nk, 2] ^ (int)temp[2]);
                this.w[row, 3] = (byte)((int)this.w[row - Nk, 3] ^ (int)temp[3]);

            }  
        }  
        //funksioni per zevendesimin e word
        private byte[] SubWord(byte[] word)
        {  
            //krijohet nje byte array i rendit 4 per te ruajtur rezultatin
            byte[] result = new byte[4];
            //per secilin rezultat vendoset vlera zevendesuese e marrur nga Sbox, pozicioni i  gjeneruar duke aplikuar right shift ne indeksin e njete te fjales per rresht, 
            //si dhe and operatori me vlere heksadecimale per kolone 
            result[0] = this.Sbox[word[0] >> 4, word[0] & 0x0f];
            result[1] = this.Sbox[word[1] >> 4, word[1] & 0x0f];
            result[2] = this.Sbox[word[2] >> 4, word[2] & 0x0f];
            result[3] = this.Sbox[word[3] >> 4, word[3] & 0x0f];
            return result;
        }
       //funksioni per rrotullim te word-it
        private byte[] RotWord(byte[] word)
        {
            //ne rezultat vendosen vlerat e fjales te zhvendosura per nje pozicion
            byte[] result = new byte[4];
            result[0] = word[1];
            result[1] = word[2];
            result[2] = word[3];
            result[3] = word[0];
            return result;
        }



    }
}
