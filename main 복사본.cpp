#include "../../HEAAN/HEAAN/src/HEAAN.h"
#include "fileReader.h"
#include "iostream"

using namespace std;
using namespace NTL;



int main() {

    string filename = "input.txt";

    // Parameters //
    
    long logp = 40; ///< Scaling Factor (larger logp will give you more accurate value)
    long logN = 17;
    long logQ = 1200; ///< Ciphertext modulus (this value should be <= logQ in "scr/Params.h")
    long logn = 3; ///< number of slot is 8=2^3 (this value should be < logN in "src/Params.h")
    long n = 1 << logn;
    long numThread = 8;
        
    // Construct and Generate Public Keys //
    srand(time(NULL));
    SetNumThreads(numThread);
    TimeUtils timeutils;
    Ring ring;
    SecretKey secretKey(ring);
    Scheme scheme(secretKey, ring);
    scheme.addLeftRotKeys(secretKey); ///< 행벡터 왼쪽 회전 (by 1,2,4,...) 할 때 필요한 키
    scheme.addRightRotKeys(secretKey); ///< 

    // **********************************
    cout << "check1" << endl;
    complex<double>* mvecX = new complex<double>[n]; // 자료 입력용 변수 정의. n=16차원 배열로 정의하였습니다.

    cout << "check2" << endl;

    readVector(mvecX, filename);    


    // **********************************
    
    cout <<"check3" << endl;

    // 총 8개의 숫자를 저장할 객체를 만듭니다.
    
    Ciphertext EncX_0;
    Ciphertext EncX_1;
    Ciphertext EncX_2;
    Ciphertext EncX_3;
    Ciphertext EncX_4;
    Ciphertext EncX_5;
    Ciphertext EncX_6;
    Ciphertext EncX_7;

    scheme.encrypt(EncX_0, mvecX[0], n, logp, logQ);
    scheme.encrypt(EncX_1, mvecX[1], n, logp, logQ);
    scheme.encrypt(EncX_2, mvecX[2], n, logp, logQ);
    scheme.encrypt(EncX_3, mvecX[3], n, logp, logQ);
    scheme.encrypt(EncX_4, mvecX[4], n, logp, logQ);
    scheme.encrypt(EncX_5, mvecX[5], n, logp, logQ);
    scheme.encrypt(EncX_6, mvecX[6], n, logp, logQ);
    scheme.encrypt(EncX_7, mvecX[7], n, logp, logQ);


    cout << "check4" << endl;

    Ciphertext EncAns; //출력부:코드 제일 말미를 보시면 이 암호문을 복호화해서 출력하는 코드가 있습니다.

    scheme.encryptZeros(EncAns, n, logp, logQ); 

    // 마지막 행은 코드를 완성한 후엔 아마도 지우셔도 됩니다. 
    // 변수형만 지정해두면 나중에 출력시 에러가 뜨는데, 알고리즘을 모두 짠 이후엔 당연히 데이터가 저장되어 있을 것이기 때문에 마지막행은 빼셔도 됩니다.

    // **********************************
    
    timeutils.start("Test time"); //시간 측정 시작용 명령어
    
    //1. 평균 구하기
    //1-1.총합 계산: cipherAdd 객체를 여러개 생성해서 숫자를 차례로 더해나갑니다.
    
    Ciphertext cipherAdd1;
    Ciphertext cipherAdd2;
    Ciphertext cipherAdd3;
    Ciphertext cipherAdd4;
    Ciphertext cipherAdd5;
    Ciphertext cipherAdd6;
    Ciphertext cipherAdd7;

    scheme.add(cipherAdd1, EncX_0, EncX_1);
    scheme.add(cipherAdd2, cipherAdd1, EncX_2);
    scheme.add(cipherAdd3, cipherAdd2, EncX_3);
    scheme.add(cipherAdd4, cipherAdd3, EncX_4);
    scheme.add(cipherAdd5, cipherAdd4, EncX_5);
    scheme.add(cipherAdd6, cipherAdd5, EncX_6);
    scheme.add(cipherAdd7, cipherAdd6, EncX_7); //마지막 객체인 cipherAdd7에 총합이 저장됩니다.

    // 1-2.총합을 개수로 나누기
    complex<double>* val_positive = new complex<double>[1];
    val_positive[0] = 1/8;

    Ciphertext cipherMult_positive;
    scheme.mult(cipherMult_positive, cipherAdd7, val_positive);
    Ciphertext cipherMultAfterReScale_positive;
    scheme.reScaleBy(cipherMultAfterReScale_positive, cipherMult_positive, logp);
    //마지막 객체인 cipherMultAfterReScale_positive에 평균값이 저장됩니다.
    
    //1-3. 분산을 구하기 위해서는 평균의 음수값이 필요하기 때문에 이를 계산해둡니다.
    complex<double>* val_negative = new complex<double>[1];
    val_negative[0] = -1/8;
    
    Ciphertext cipherMult_negative;
    scheme.mult(cipherMult_negative, cipherAdd7, val_negative);
    Ciphertext cipherMultAfterReScale_negative;
    scheme.reScaleBy(cipherMultAfterReScale_negative, cipherMult_negative, logp);
    
    // 마지막 객체인 cipherMultAfterReScale_negative에 평균의 음수값이 저장됩니다.
    
    // **********************************
    // 2. 분산 구하기
    // 2-1. 각 숫자에서 평균 빼기
    
    // 아래 객체들을 배열에 저장해서 for 문을 정말 돌리고 싶은데.. 씨언어 배열 타입을 잘 몰라서 보기 힘들지만 일일이 풀어서 적었습니다.
    Ciphertext varAdd_0;
    Ciphertext varAdd_1;
    Ciphertext varAdd_2;
    Ciphertext varAdd_3;
    Ciphertext varAdd_4;
    Ciphertext varAdd_5;
    Ciphertext varAdd_6;
    Ciphertext varAdd_7;
    
    scheme.add(varAdd_0, EncX_0, cipherMultAfterReScale_negative)
    scheme.add(varAdd_1, EncX_1, cipherMultAfterReScale_negative)
    scheme.add(varAdd_2, EncX_2, cipherMultAfterReScale_negative)
    scheme.add(varAdd_3, EncX_3, cipherMultAfterReScale_negative)
    scheme.add(varAdd_4, EncX_4, cipherMultAfterReScale_negative)
    scheme.add(varAdd_5, EncX_5, cipherMultAfterReScale_negative)
    scheme.add(varAdd_6, EncX_6, cipherMultAfterReScale_negative)
    scheme.add(varAdd_7, EncX_7, cipherMultAfterReScale_negative)

    //2-2. (2-1)의 결과값을 제곱하기
    
    Ciphertext varSqr_0;
    Ciphertext varSqr_1;
    Ciphertext varSqr_2;
    Ciphertext varSqr_3;
    Ciphertext varSqr_4;
    Ciphertext varSqr_5;
    Ciphertext varSqr_6;
    Ciphertext varSqr_7;
    
    scheme.mult(varSqr_0, varAdd_0, varAdd_0);
    scheme.mult(varSqr_1, varAdd_1, varAdd_1);
    scheme.mult(varSqr_2, varAdd_2, varAdd_2);
    scheme.mult(varSqr_3, varAdd_3, varAdd_3);
    scheme.mult(varSqr_4, varAdd_4, varAdd_4);
    scheme.mult(varSqr_5, varAdd_5, varAdd_5);
    scheme.mult(varSqr_6, varAdd_6, varAdd_6);
    scheme.mult(varSqr_7, varAdd_7, varAdd_7);
    
    //2-3. 2-2에서 계산한 값들의 합 구하기
    
    Ciphertext varTotal_0;
    Ciphertext varTotal_1;
    Ciphertext varTotal_2;
    Ciphertext varTotal_3;
    Ciphertext varTotal_4;
    Ciphertext varTotal_5;
    Ciphertext varTotal_6;
    
    scheme.add(varTotal_0, varSqr_0, varSqr_1);
    scheme.add(varTotal_1, varTotal_0, varSqr_2);
    scheme.add(varTotal_2, varTotal_0, varSqr_3);
    scheme.add(varTotal_3, varTotal_0, varSqr_4);
    scheme.add(varTotal_4, varTotal_0, varSqr_5);
    scheme.add(varTotal_5, varTotal_0, varSqr_6);
    scheme.add(varTotal_6, varTotal_0, varSqr_7);

    // 마지막 객체인 varTotal_6에 제곱값들의 합 저장됨
    
    //2-4. 편차의 제곱합을 갯수로 나누기
    
    //앞서 1/8은 val_positive 로 선언됨.
    
    Ciphertext varFinal;
    
    scheme.mult(varFinal, val_positive, varTotal_6);
    // 앞서 구한 편차의 제곱합을 갯수(8)의 역수와 곱함. 여기서 계산되는 varFinal은 우리가 구하려는 분산의 최종값.

    timeutils.stop("Test time");

    // **********************************
    
    complex<double>* dmult = scheme.decrypt(secretKey, varFinal);
 
    // **********************************
}
