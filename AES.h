#ifndef AES_h__
#define AES_h__

#include <string>
#include <exception>
using namespace std;

class AES
{
protected:
    AES();
    ~AES();
public:
    static string encrypt(string input, string key);
    static string decrypt(string input, string key);
};

#endif // AES_h__
