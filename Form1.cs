using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace DetyraAES
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }
        private AES.KeySize keysize;
        private void Encrypt_Click(object sender, EventArgs e)
        {
            if (radioButton1.Checked)
                keysize = AES.KeySize.Bits128;
            else if (radioButton2.Checked)
                keysize = AES.KeySize.Bits192;
            else
                keysize = AES.KeySize.Bits256;

            byte[] plainText = new byte[16];
            byte[] cipherText = new byte[16];

            plainText = Encoding.Unicode.GetBytes(textBox1.Text.PadRight(8, ' '));

            DetyraAES.AES a = new AES(keysize, new byte[16]);
            a.Cipher(plainText, cipherText);
            //textBox2.Text = Encoding.Unicode.GetString(cipherText);
            textBox2.Text = Encoding.Unicode.GetString(cipherText);
        }

        private void Decrypt_Click(object sender, EventArgs e)
        {
            if (radioButton1.Checked)
                keysize = AES.KeySize.Bits128;
            else if (radioButton2.Checked)
                keysize = AES.KeySize.Bits192;
            else
                keysize = AES.KeySize.Bits256;

            byte[] cipherText = new byte[16];
            byte[] decipheredText = new byte[16];

            cipherText = Encoding.Unicode.GetBytes(textBox2.Text);
            DetyraAES.AES a = new AES(keysize, new byte[16]);
            a.InvCipher(cipherText, decipheredText);
            textBox3.Text = Encoding.Unicode.GetString(decipheredText); ;
        }
    }
}
