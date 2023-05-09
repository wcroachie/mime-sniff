sniffing mimes is no easy task, especially if the mimes are uncomfortable with programmers sniffing them...

I created this hellish code for the sole purpose of automatically detecting a file type from raw binary data. I wrote it from scratch, cross-referencing many sources. Here are some good ones:
https://mimesniff.spec.whatwg.org/#binary-data-byte
https://en.wikipedia.org/wiki/List_of_file_signatures
https://www.garykessler.net/library/file_sigs.html

theres quite a few other libraries out there written in typescript or for nodejs and if you use either of those things you should probably be using that instead of my code because youre smarter than me.

PS gary kessler i am literally begging you to be consistent when you are writing html because getting all of those byte patterns would be a lot simpler if your html was simpler and i could just request it and parse it with regex but instead I had to hand-copy a lot of these!!
