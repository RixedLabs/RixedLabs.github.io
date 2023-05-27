---

layout: post
title: "A small tale on Anti-RE : Part 1"
categories: Reverse-Engineering
author: "ElementalX"
tags: anti-re
---


Hey readers, hope everyone is doing pretty decent. After writing the very [first blog](/reverse-engineering/2023/01/21/A-small-tale-on-Anti-RE-_-Part-0.html) for this series of exploring anti-reverse engineering techniques, I decided to explore some new topics in this part of blog. I will try my best to explain, I hope you will understand reading this small blog!

## Contents
-   Preface
-   Understanding Code Transposition.
-   Author's two cents.
-   Resources & Contributors.

## Preface
After the very first blog, in which we encountered, dead code and opaque predicate, which also included some examples of it, I encountered [this](https://www.virustotal.com/gui/file/fc04e80d343f5929aea4aac77fb12485c7b07b3a3d2fc383d68912c9ad0666da) unknown packer, which was dropping Smokeloader, upon disassembly it was found that this sample included bunch of opaque predicates and UN-necessary loops just to hinder the analysis time, turns out I had to use `F5` less number of times after the first blog, keeping in mind increasing my skill set and decrease usage of `F5` in IDA, in this blog, we will focus on understanding code transposition, with code examples if possible. Just before getting started thanks to researchers [Thomas Roccia](https://twitter.com/fr0gger_) & [Jean-Pierre LESUEUR](https://twitter.com/darkcodersc) for maintaining a very cool collection on these anti-analysis project known as [Unprotect Project](https://unprotect.it/) . Let us now get started.

## Understanding Code Transposition
Code transposition is basically an anti-disassembly technique. Before moving ahead to understanding anti-disassembly, it is useful to have an understanding of disassembly and how tools like `IDA` parse the binary and generate disassembly.

In my previous blog, I have explained [two types of algorithms](https://rixed-labs.medium.com/a-small-tale-on-anti-re-part-0-95d05ed17580) which generate disassembly that is `Linear-Sweep` Algorithm & `Recursive Descent `Algorithm, and how certain techniques take advantage of these algorithms to include useless loops. This technique is also using an advantage of this current algorithms.

Code `transposition` as it means re-arranging something, but in this case it's re-arranging actual code, bringing no actual change to the meaning or the working of a program.

Let us understand it this way:
```c
hello();\
name();\
age();\
mood();\
time();\
bye();
```

There is a normal C program which has like four functions known as `hello()` which prompts greeting message to the user, other function `name()` asks user the name of the user, next function asks about the `mood() `of the user whether he is happy, sad or mid, and finally it greets `bye()` .

Now, let us assume we will apply code transposition in this program, and `group` this set of functions into three i.e., `about` & `greetings` & `normal` , where under `about` we can group the functions `name` & `age` , under `greetings `we can add `hello()` & `bye` and under about we can categorize `time()` & `mood` .

So, now after `first `set of transposition it looks something like this :
```c
greetings(){

    hello();\
    buy();\
}

about(){

   name();\
   age();\
}

random() {

mood();\
time();

}
```
Wait! Wasn't `name()` function supposed to be executed just after `hello()` function? 😅

Now, a very go-to technique would be to add some inline assembly to perform an indirect jump or a call to a function. Let us now, perform out second and last set of code transposition.
```c
greetings(){

    hello();\
    asm("jmp %0" : : "r"(&name));\
    buy();\
}

about(){

   name();\
   age();\
}

random() {

mood();\
time();

}
```

So, here we can see that a unconditional `jmp` instruction was added, whereas it could have been a part of the very first program. This dummy example was very easy to understand and flow could easily be detected, and can be said that this was `controlled` transposition and was not random.

Now, we will see two different cases where the arrangement of the set of functions are random, although the behavior of the code will be very same, and in the other case we will see re-arrangement of functions depending on user argument which leads to behavior change.

*# Case 1 : Code Transposition without change in behavior*

Here in this case this is the simple C++ Program :
```c
#include <iostream>\
#include <string>

using namespace std;

void greet() {\
    cout << "Hello! Welcome to the program.\n";\
}

string askName() {\
    string name;\
    cout << "What's your name?\n";\
    cin >> name;\
    return name;\
}

string askMood() {\
    string mood;\
    cout << "How are you feeling today?\n";\
    cin >> mood;\
    return mood;\
}

string askDayOfWeek() {\
    string day;\
    cout << "What day of the week is it today?\n";\
    cin >> day;\
    return day;\
}

void sayGoodbye(string name) {\
    cout << "Goodbye, " << name << "! Thanks for using the program.\n";\
}

int main() {\
    greet();\
    string name = askName();\
    string mood = askMood();\
    string day = askDayOfWeek();\
    sayGoodbye(name);\
    return 0;\
}
```
The working of this program is just like the one which we saw in the example, now let us compile it in check out the disassembly.

![](https://miro.medium.com/v2/resize:fit:875/1*t7546ZgBqLkDTuZFpkcU_A.png)

The disassembly of this program looks very straightforward, that is call to functions, in a proper order just like the code. Now, let check ahead the debugging view by setting up a break point.

![](https://miro.medium.com/v2/resize:fit:875/1*W8O1MUVNIWRmlC5HnQ2atA.gif)

As, we trace through the code, it looks very simple and straight forward just as it should be without hindering the analysis time.

Now let us make some changes in this code, which are slightly predictable or with little added transposition.
```c
#include <iostream>\
#include <string>\
#include <chrono>\
#include <thread>

using namespace std;

void greet();\
string askName();\
string askMood();\
string askDayOfWeek();\
void sayGoodbye(string name);\
void sleep_and_jump(string(*func)());

int main() {\
    greet();\
    string name = askName();\
    string mood = askMood();\
    string day = askDayOfWeek();\
    sayGoodbye(name);\
    return 0;\
}

void greet() {\
    cout << "Hello! Welcome to the program.\n";\
    sleep_and_jump(&askMood);\
}

string askName() {\
    string name;\
    cout << "What's your name?\n";\
    cin >> name;\
    return name;\
}

string askMood() {\
    string mood;\
    cout << "How are you feeling today?\n";\
    cin >> mood;\
    return mood;\
}

string askDayOfWeek() {\
    string day;\
    cout << "What day of the week is it today?\n";\
    cin >> day;\
    return day;\
}

void sayGoodbye(string name) {\
    cout << "Goodbye, " << name << "! Thanks for using the program.\n";\
}

void sleep_and_jump(string(*func)()) {\
    this_thread::sleep_for(chrono::seconds(10));\
    return;\
}
```
In this code, we have added two small changes in terms of `transposition` which is pretty revertible but it will hinder a bit of analysis time, the changes in this code is adding one more function which will sleep for 10 seconds then jump to that function called `askMood` which is not supposed to be `executed` and wont execute and then will just normally call the `askName()` function.

Let us execute, and check whether it is working as intended.

![](https://miro.medium.com/v2/resize:fit:875/1*x6rGyg0CCNqQXMpHuOFbuA.gif)

Looks, good! It is executing as expected, not let us go ahead with loading this binary into IDA, and check out how it hinders the static and dynamic analysis after we set a break-point.

![](https://miro.medium.com/v2/resize:fit:875/1*JHQ3J939rCF1e1a4K99DKQ.png)

![](https://miro.medium.com/v2/resize:fit:709/1*ycEUwf1GxBngHso10NzcSA.png)

![](https://miro.medium.com/v2/resize:fit:875/1*ZaHlWxhjo2AjZcyJXqM-9g.png)

Well, we can now see that although there was negligible change to the actual working and order of functions, the disassembly now looks slight complex with bunch of `call` and other instructions. Now let us set a break-point and check out the tracing.

![](https://miro.medium.com/v2/resize:fit:875/1*khK2nITt9SJxd6nLxLdCYQ.gif)

After, setting a break-point we if we step into each instruction, we can see there's some time waste , which can simply be avoided by stepping over. So this was the very first example of applying small transposition which can be easily be understood and is in a predictable manner.

Next, we will see the case which is using random numbers to perform `transposition` which will affect the behavior of the working of program.

*# Case 2: Code Transposition with change in behavior.*

Now, moving ahead to the second case, where will use some code transposition and which will do some sort of behavior changes in our program, and might affect the working of it.

Let us first write a very small C program and check out it's disassembly.
```c
#include <stdio.h>

void greet_hello();\
void ask_mood();\
void ask_age();\
void greet_goodbye();

int main() {\
    greet_hello();\
    ask_mood();\
    ask_age();\
    greet_goodbye();

    return 0;\
}

void greet_hello() {\
    printf("Hello, how are you doing?\n");\
}

void ask_mood() {\
    printf("How is your mood?\n");\
}

void ask_age() {\
    printf("What's your age?\n");\
}

void greet_goodbye() {\
    printf("Goodbye and thanks for using the program.\n");\
}
```
This simple C program , does four small things, greets `hello` , then asks how is user's `mood` , then asks user's `age` and then greets `goodbye()` . Now let us compile this and check the disassembly.

![](https://miro.medium.com/v2/resize:fit:875/1*3aTdekX00f2Z95RdC_As9w.png)

That looks pretty straight-forward, calls to 4 different functions in a orderly manner, now let us set a break-point and figure out the behavior while tracing.

![](https://miro.medium.com/v2/resize:fit:875/1*d13Az7M6D5D3K8KZR3Fkiw.gif)

Looks, neat!

Now, let us add a bit of `transposition` in the code which is random every time we execute it that is in layman terms, out of every four functions any one can execute each time, and the order of execution of behavior is slightly changed.
```c
#include <stdio.h>\
#include <stdlib.h>\
#include <time.h>

void greet_user();\
void ask_age();\
void ask_mood();\
void say_goodbye();

int main() {\
    int random_num;\
    srand(time(NULL));\
    random_num = rand() % 4 + 1;

    switch(random_num) {\
        case 1:\
            greet_user();\
            ask_age();\
            ask_mood();\
            say_goodbye();\
            break;\
        case 2:\
            ask_age();\
            greet_user();\
            ask_mood();\
            say_goodbye();\
            break;\
        case 3:\
            ask_mood();\
            greet_user();\
            ask_age();\
            say_goodbye();\
            break;\
        case 4:\
            say_goodbye();\
            greet_user();\
            ask_age();\
            ask_mood();\
            break;\
    }

    return 0;\
}

void greet_user() {\
    printf("Hello, how are you doing?\n");\
}

void ask_age() {\
    printf("What's your age?\n");\
}

void ask_mood() {\
    printf("How is your mood?\n");\
}

void say_goodbye() {\
    printf("Goodbye and thanks for using the program.\n");\
}
```
Now, in this case we have added a small switch case which varies according to the result, and in this case the result is the number of the function. Now let us compile this binary and load up in IDA and check the disassembly.

![](https://miro.medium.com/v2/resize:fit:875/1*XBsOKlS2Gb7W-FmewKr6gQ.png)

![](https://miro.medium.com/v2/resize:fit:875/1*YZQdN15diNpTOR3Fin98LQ.png)

Looks a bit of complex isn't it? The same program with same number of functions and task now looks a bit of time taking. Let us execute this twice and check whether it actually works as it supposed to be or is there any issue.

![](https://miro.medium.com/v2/resize:fit:685/1*u_pGFPxP18AmxTP_Xh8r_g.png)

As expected, this randomizes function every other time of execution.

Let us trace this program now, and check out whether is that time taking or just simple.

![](https://miro.medium.com/v2/resize:fit:875/1*QCVzxfDlebDgxps-M1A0EA.gif)

In this case too, stepping over and jumping to selected branches made dynamic analysis bit easy and straight forward in this easy example of random `code transposition` .

So*what's now?*

These were just minimal examples with very easy piece of code, in real life software/application the bar of code transposition may be high and sometimes not predictable in a go. But can easily be defeated by removing useless jumps like the ones in example and sometimes experience and time can help out too. I did not find any exact tool or plugin which can aid with this problem just like my previous blog. But if you find something relevant, your most welcome to add it in the comments as feedback!

## Author's two cents
This blog, just like my previous blog discussed very briefly about code transposition with some examples. In next blog of this series, I will be experimenting with opcode obfuscation depending on my skill-set. If you find any sort of dumb mistake please help me out to fix it with a simple comment or reach me out at our [discord server](https://discord.gg/CBRTkh5MFB). I will be happy to learn through mistakes. Thanks a lot for reading.

## Resources
-   <https://unprotect.it/technique/code-transposition/>
-   [https://www.researchgate.net/figure/Code-Transposition-based-on-Unconditional-Branches_fig2_22142099](https://www.researchgate.net/figure/Code-Transposition-based-on-Unconditional-Branches_fig2_221420990)
-   Stack Overflow.
